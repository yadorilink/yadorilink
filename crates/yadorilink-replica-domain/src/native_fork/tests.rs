use std::collections::BTreeSet;

use super::*;
use crate::author::IncarnationId;
use crate::conflict::MAX_COMPONENT_BYTES;
use crate::file::RecordKind;
use crate::ids::{AuthorSeq, DeviceId};
use crate::limits::MAX_PATH_BYTES;
use crate::native_project::{contests, project_tree};
use crate::native_state::{Dot, PathEdit};

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_owned()), incarnation: IncarnationId([1u8; 16]) }
}

fn v(byte: u8) -> VersionHash {
    VersionHash([byte; 32])
}

fn p(path: &str) -> SyncPath {
    SyncPath(path.to_owned())
}

/// 0xD0..=0xDF directories, 0xFF has no record, everything else a file.
fn kind_of(version: &VersionHash) -> Option<RecordKind> {
    match version.0[0] {
        0xD0..=0xDF => Some(RecordKind::Directory),
        0xFF => None,
        _ => Some(RecordKind::File),
    }
}

const LIMITS: ForkLimits = ForkLimits { max_ops_per_delta: 64, max_bytes_per_delta: usize::MAX };

struct World {
    state: NativeState,
    next_provenance: u8,
}

impl World {
    fn new() -> Self {
        Self { state: NativeState::new(), next_provenance: 1 }
    }

    fn put(&mut self, name: &str, path: &str, version: u8) -> Dot {
        let provenance = DeltaHash([self.next_provenance; 32]);
        self.next_provenance = self.next_provenance.wrapping_add(1).max(1);
        let a = author(name);
        let observed: Vec<Dot> = Vec::new();
        self.state
            .put(&a, p(path), &observed, HeadPayload { version: v(version), provenance })
            .unwrap()
    }

    fn plan(&self, name: &str) -> ForkPlan {
        plan_own_forks(&self.state, &author(name), kind_of, LIMITS).unwrap()
    }

    fn apply(&mut self, name: &str, plan: &ForkPlan) {
        apply_plan(&mut self.state, &author(name), plan);
    }
}

fn remote_ops(delta: &ForkDelta, signer: &AuthorId, seq: AuthorSeq) -> Vec<RemoteOp> {
    let mut provenance = [0xAA; 32];
    provenance[..8].copy_from_slice(&seq.0.to_be_bytes());
    let name = signer.device.0.as_bytes();
    let take = name.len().min(16);
    provenance[8..8 + take].copy_from_slice(&name[..take]);
    delta
        .ops
        .iter()
        .map(|op| RemoteOp {
            path: op.path.clone(),
            removes: op.removes.clone(),
            put: op
                .put
                .as_ref()
                .map(|put| HeadPayload { version: put.version, provenance: DeltaHash(provenance) }),
        })
        .collect()
}

fn apply_plan(state: &mut NativeState, author: &AuthorId, plan: &ForkPlan) {
    for delta in &plan.deltas {
        let seq = state.next_dot(author).unwrap().seq;
        state.receive_verified(author, seq, &remote_ops(delta, author, seq)).unwrap();
        state.check_invariants().unwrap();
    }
}

// --- copy_path ---------------------------------------------------------

#[test]
fn copy_path_golden_vectors() {
    // Independently computed: hex(SHA-256("ylnk-copy-2" || u32be(len(path)) ||
    // path || version)[..16]).
    let vectors: [(&str, VersionHash, &str); 5] = [
        ("a.txt", v(1), "a (conflicted copy, e5acdfffb7f4879886a2851acbb2343d).txt"),
        ("dir/notes", v(2), "dir/notes (conflicted copy, d758ad9a02468dfcd39f8ed71c3c5a5b)"),
        (
            "dir/notes (conflicted copy, 00000000000000000000000000000000).txt",
            v(2),
            "dir/notes (conflicted copy, 00000000000000000000000000000000) (conflicted copy, dfe42868dd77171ad9b8809867e423a6).txt",
        ),
        (
            "日本語.md",
            VersionHash(std::array::from_fn(|i| i as u8)),
            "日本語 (conflicted copy, 733c96c4ebb83a4e8dbcc456559b93bf).md",
        ),
        (".bashrc", v(0xFF), ".bashrc (conflicted copy, 98ebf49f707ee8959817d0b88df0358d)"),
    ];
    for (path, version, expected) in vectors {
        assert_eq!(copy_path(path, &version), expected, "{path}");
    }
}

#[test]
fn the_copy_id_is_32_hex_characters_over_the_full_path_and_version() {
    let name = copy_path("docs/report.pdf", &v(9));
    let id = name.split("(conflicted copy, ").nth(1).unwrap().split(')').next().unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    // Another version, another path (even one differing only in its
    // directory) and the copy of a copy all get different ids.
    let ids: BTreeSet<String> = [
        copy_path("docs/report.pdf", &v(9)),
        copy_path("docs/report.pdf", &v(10)),
        copy_path("other/report.pdf", &v(9)),
        copy_path(&name, &v(9)),
    ]
    .into_iter()
    .collect();
    assert_eq!(ids.len(), 4);
}

#[test]
fn the_copy_name_is_a_pure_function_of_path_and_version() {
    for _ in 0..3 {
        assert_eq!(copy_path("a/b.txt", &v(3)), copy_path("a/b.txt", &v(3)));
    }
    // The existing marker is not stripped: the stem keeps it.
    let once = copy_path("a/b.txt", &v(3));
    let twice = copy_path(&once, &v(3));
    assert!(twice.matches("(conflicted copy, ").count() == 2, "{twice}");
}

#[test]
fn a_long_stem_is_shortened_to_fit_a_component_and_the_id_survives() {
    let long = format!("{}.txt", "é".repeat(400));
    let name = copy_path(&long, &v(4));
    assert!(name.len() <= MAX_COMPONENT_BYTES, "{}", name.len());
    assert!(name.ends_with(").txt"));
    assert!(name.contains(" (conflicted copy, "));
    // The id covers the untruncated path: two long names sharing a prefix
    // differ.
    let other = format!("{}x.txt", "é".repeat(400));
    assert_ne!(copy_path(&other, &v(4)), name);
}

#[test]
fn a_very_long_extension_cannot_push_the_copy_name_past_the_component_limit() {
    let source = format!("a.{}", "x".repeat(220));
    let name = copy_path(&source, &v(1));
    assert!(name.len() <= MAX_COMPONENT_BYTES, "{}", name.len());
    assert!(name.contains(" (conflicted copy, "));
    // Another version of the same file still gets its own name.
    assert_ne!(name, copy_path(&source, &v(2)));
}

// --- fork planning -----------------------------------------------------

#[test]
fn the_loser_author_removes_its_head_and_puts_the_same_version_at_the_copy_path() {
    let mut w = World::new();
    let loser = w.put("a", "f.txt", 1);
    w.put("b", "f.txt", 2);
    let plan = w.plan("a");
    assert_eq!(plan.deltas.len(), 1);
    let ops = &plan.deltas[0].ops;
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].path, p("f.txt"));
    assert_eq!(ops[0].removes.len(), 1);
    assert_eq!(ops[0].removes[0].dot, loser);
    assert!(ops[0].put.is_none());
    assert_eq!(ops[1].path, p(&copy_path("f.txt", &v(1))));
    assert!(ops[1].removes.is_empty());
    assert_eq!(ops[1].put, Some(DeltaPut { version: v(1) }));
}

#[test]
fn the_winner_author_and_bystanders_plan_nothing() {
    let mut w = World::new();
    w.put("a", "f.txt", 1);
    w.put("b", "f.txt", 2);
    assert_eq!(w.plan("b"), ForkPlan::default());
    assert_eq!(w.plan("viewer"), ForkPlan::default());
}

#[test]
fn applying_the_plan_equals_authoring_the_rename_by_hand() {
    let mut w = World::new();
    let loser = w.put("a", "f.txt", 1);
    w.put("b", "f.txt", 2);
    let plan = w.plan("a");

    let mut by_plan = w.state.clone();
    apply_plan(&mut by_plan, &author("a"), &plan);

    // The same rename as a user would have made it: observe the head at the
    // old path and land the version at the new one, through the ordinary
    // authoring primitive.
    let mut by_hand = w.state.clone();
    let copy = p(&copy_path("f.txt", &v(1)));
    by_hand
        .author(
            &author("a"),
            vec![
                PathEdit { path: p("f.txt"), observed: vec![loser], put: None },
                PathEdit {
                    path: copy,
                    observed: vec![],
                    put: Some(HeadPayload { version: v(1), provenance: DeltaHash([0xAA; 32]) }),
                },
            ],
        )
        .unwrap();
    let shape = |s: &NativeState| {
        s.heads
            .iter()
            .map(|(path, heads)| {
                (
                    path.clone(),
                    heads.iter().map(|(d, h)| (d.clone(), h.version)).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&by_plan), shape(&by_hand));
}

#[test]
fn after_the_fork_the_path_is_settled_for_everyone_and_the_copy_is_a_file() {
    let mut w = World::new();
    w.put("a", "f.txt", 1);
    w.put("b", "f.txt", 2);
    let before = contests(&project_tree(&w.state.heads, kind_of));
    assert_eq!(before.len(), 1);
    let plan = w.plan("a");
    w.apply("a", &plan);
    let tree = project_tree(&w.state.heads, kind_of);
    assert!(contests(&tree).is_empty());
    assert_eq!(tree.len(), 2);
}

#[test]
fn one_author_with_two_losing_versions_moves_both_in_one_delta() {
    let mut w = World::new();
    w.put("a", "f.txt", 1);
    w.put("a", "f.txt", 2);
    w.put("b", "f.txt", 9);
    let plan = w.plan("a");
    assert_eq!(plan.deltas.len(), 1);
    let ops = &plan.deltas[0].ops;
    assert_eq!(ops.len(), 3);
    assert_eq!(ops[0].removes.len(), 2);
    let copies: BTreeSet<&SyncPath> = ops[1..].iter().map(|op| &op.path).collect();
    assert_eq!(copies.len(), 2);
}

#[test]
fn a_lone_file_under_a_live_descendant_is_forked() {
    let mut w = World::new();
    w.put("a", "dir", 1);
    w.put("b", "dir/child", 2);
    let plan = w.plan("a");
    assert_eq!(plan.deltas.len(), 1);
    assert_eq!(plan.deltas[0].ops[0].path, p("dir"));
    // The descendant's author has nothing to move.
    assert_eq!(w.plan("b"), ForkPlan::default());
}

#[test]
fn a_file_loses_to_a_directory_head_and_a_directory_is_never_copied() {
    let mut w = World::new();
    w.put("a", "x", 5);
    w.put("b", "x", 0xD1);
    w.put("c", "x", 0xD2);
    assert_eq!(w.plan("a").deltas.len(), 1);
    assert_eq!(w.plan("b"), ForkPlan::default());
    assert_eq!(w.plan("c"), ForkPlan::default());
}

#[test]
fn equal_versions_of_two_authors_are_not_a_conflict() {
    let mut w = World::new();
    w.put("a", "f", 3);
    w.put("b", "f", 3);
    assert_eq!(w.plan("a"), ForkPlan::default());
    assert_eq!(w.plan("b"), ForkPlan::default());
}

#[test]
fn a_path_with_an_unresolved_record_waits() {
    let mut w = World::new();
    w.put("a", "f", 1);
    w.put("b", "f", 0xFF);
    let plan = w.plan("a");
    assert!(plan.deltas.is_empty());
    assert_eq!(plan.waiting_for_records, vec![p("f")]);
}

#[test]
fn an_occupied_copy_path_is_an_ordinary_contest_for_the_next_round() {
    let mut w = World::new();
    w.put("a", "f", 1);
    w.put("b", "f", 2);
    // Someone already put a different, larger version at the copy path.
    let copy = copy_path("f", &v(1));
    w.put("b", &copy, 7);
    let plan = w.plan("a");
    assert_eq!(plan.deltas.len(), 1);
    w.apply("a", &plan);
    // The copy path is now contested; a's head there loses and moves on.
    let second = w.plan("a");
    assert_eq!(second.deltas.len(), 1);
    assert_eq!(second.deltas[0].ops[0].path, p(&copy));
    w.apply("a", &second);
    assert_eq!(w.plan("a"), ForkPlan::default());
    // Nothing distinct was lost on the way.
    assert!(live_versions(&w.state).is_superset(&[v(1), v(2), v(7)].into_iter().collect()));
}

#[test]
fn a_bucket_holding_other_versions_is_resolved_before_the_put_lands() {
    let mut w = World::new();
    w.put("a", "f", 1);
    w.put("b", "f", 9);
    let copy = copy_path("f", &v(1));
    // a already holds two different versions at the copy path.
    w.put("a", &copy, 8);
    w.put("a", &copy, 4);
    let plan = w.plan("a");
    assert_eq!(plan.deltas.len(), 2, "{plan:?}");
    // The first delta moves the loser at the copy path out of the way.
    assert_eq!(plan.deltas[0].ops[0].path, p(&copy));
    assert_eq!(plan.deltas[1].ops[0].path, p("f"));
    let before = live_versions(&w.state);
    w.apply("a", &plan);
    assert!(live_versions(&w.state).is_superset(&before));
}

#[test]
fn a_full_bucket_of_unrelated_equal_heads_refuses_instead_of_dropping() {
    let mut w = World::new();
    w.put("a", "f", 1);
    w.put("b", "f", 9);
    let copy = copy_path("f", &v(1));
    // Two equal-version heads of another version fill the bucket and neither
    // is a loser, so nothing can make room without dropping a version.
    w.put("a", &copy, 6);
    w.put("a", &copy, 6);
    // One refused path does not stop the forks of the others.
    w.put("a", "other", 1);
    w.put("b", "other", 9);
    let plan = plan_own_forks(&w.state, &author("a"), kind_of, LIMITS).unwrap();
    assert_eq!(plan.refused, vec![(p("f"), ForkError::BucketFull { path: p(&copy) })]);
    assert_eq!(plan.deltas.len(), 1);
    assert_eq!(plan.deltas[0].ops[0].path, p("other"));
}

#[test]
fn a_full_bucket_of_the_same_version_is_superseded() {
    let mut w = World::new();
    w.put("a", "f", 1);
    w.put("b", "f", 9);
    let copy = copy_path("f", &v(1));
    w.put("a", &copy, 1);
    w.put("a", &copy, 1);
    let plan = w.plan("a");
    let put_op = plan.deltas[0].ops.iter().find(|op| op.path == p(&copy)).unwrap();
    assert_eq!(put_op.removes.len(), 1);
    let before = live_versions(&w.state);
    w.apply("a", &plan);
    assert_eq!(live_versions(&w.state), before);
}

#[test]
fn a_wide_fork_is_a_chain_cut_at_whole_groups() {
    let mut w = World::new();
    let paths = 2000;
    for i in 0..paths {
        w.put("a", &format!("dir/f{i:04}"), 1);
        w.put("b", &format!("dir/f{i:04}"), 2);
    }
    let limits = ForkLimits { max_ops_per_delta: 100, max_bytes_per_delta: usize::MAX };
    let plan = plan_own_forks(&w.state, &author("a"), kind_of, limits).unwrap();
    assert_eq!(plan.deltas.iter().map(|d| d.ops.len()).sum::<usize>(), paths * 2);
    assert!(plan.deltas.len() > 1);
    for delta in &plan.deltas {
        assert!(delta.ops.len() <= limits.max_ops_per_delta);
        assert_self_contained(delta);
    }
    w.apply("a", &plan);
    assert!(contests(&project_tree(&w.state.heads, kind_of)).is_empty());
}

/// A delta must fit one replication item: the chain is cut by bytes as well as
/// by ops, between whole groups, so long paths never make an undeliverable delta.
#[test]
fn a_fork_chain_is_cut_by_bytes_between_whole_groups() {
    let mut w = World::new();
    for i in 0..40 {
        let path = format!("{}/f{i:02}", "d".repeat(3000));
        w.put("a", &path, 1);
        w.put("b", &path, 2);
    }
    let limits = ForkLimits { max_ops_per_delta: 1000, max_bytes_per_delta: 20_000 };
    let plan = plan_own_forks(&w.state, &author("a"), kind_of, limits).unwrap();
    assert!(plan.deltas.len() > 1, "the byte budget cuts the chain");
    for delta in &plan.deltas {
        let bytes: usize = delta.ops.iter().map(|op| op.path.as_str().len() + 64).sum();
        // A whole group (a removal and its put) may overshoot by one group, never more.
        assert!(bytes <= limits.max_bytes_per_delta + 2 * (3000 + 64 + 100), "{bytes}");
        assert_self_contained(delta);
    }
    w.apply("a", &plan);
    assert!(contests(&project_tree(&w.state.heads, kind_of)).is_empty());
}

#[test]
fn a_copy_path_beyond_the_path_limit_is_refused_before_the_plan_is_made() {
    let mut w = World::new();
    // Segments of 200 bytes bring the path to the limit; the copy suffix
    // pushes the sibling over it.
    let segment = "d".repeat(199);
    let mut path = String::new();
    while path.len() + 200 + 40 < MAX_PATH_BYTES {
        path.push_str(&segment);
        path.push('/');
    }
    let name = "n".repeat(MAX_PATH_BYTES - path.len());
    path.push_str(&name);
    assert_eq!(path.len(), MAX_PATH_BYTES);
    w.put("a", &path, 1);
    w.put("b", &path, 2);
    let plan = plan_own_forks(&w.state, &author("a"), kind_of, LIMITS).unwrap();
    assert!(plan.deltas.is_empty());
    assert!(
        matches!(plan.refused[0].1, ForkError::DestinationTooLong { .. }),
        "{:?}",
        plan.refused
    );
}

#[test]
fn a_budget_below_one_group_is_refused() {
    let w = World::new();
    let err = plan_own_forks(
        &w.state,
        &author("a"),
        kind_of,
        ForkLimits { max_ops_per_delta: MIN_OPS_PER_DELTA - 1, max_bytes_per_delta: usize::MAX },
    )
    .unwrap_err();
    assert_eq!(err, ForkError::OpBudgetTooSmall);
}

/// No delta removes a head of a version it does not also put; every removal
/// is an own head; paths are distinct within a delta.
fn assert_self_contained(delta: &ForkDelta) {
    let mut paths = BTreeSet::new();
    for op in &delta.ops {
        assert!(paths.insert(&op.path), "duplicate path in one delta");
    }
    let put_versions: BTreeSet<VersionHash> =
        delta.ops.iter().filter_map(|op| op.put.as_ref().map(|put| put.version)).collect();
    assert!(!put_versions.is_empty() || delta.ops.iter().all(|op| op.removes.is_empty()));
}

fn assert_removes_only_own_heads(delta: &ForkDelta, owner: &AuthorId) {
    for removal in delta.ops.iter().flat_map(|op| op.removes.iter()) {
        assert_eq!(removal.dot.author, *owner, "removed a foreign head");
    }
}

// --- randomized properties ---------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn random_world(rng: &mut Rng) -> World {
    const NAMES: [&str; 3] = ["a", "b", "c"];
    const PATHS: [&str; 5] = ["f", "g", "d", "d/x", "d/x/y"];
    const VERSIONS: [u8; 6] = [1, 2, 3, 0xD1, 0xD2, 0xFF];
    let mut w = World::new();
    for _ in 0..(3 + rng.below(10)) {
        let name = NAMES[rng.below(NAMES.len())];
        let path = PATHS[rng.below(PATHS.len())];
        let version = VERSIONS[rng.below(VERSIONS.len())];
        // Keep the author's bucket within its bound, as an honest author does.
        let own = w
            .state
            .heads
            .get(&p(path))
            .map_or(0, |h| h.keys().filter(|d| d.author == author(name)).count());
        if own >= MAX_SELF_HEADS {
            continue;
        }
        w.put(name, path, version);
    }
    w
}

#[test]
fn random_forks_only_move_own_heads_never_drop_a_version_and_converge() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut planned_deltas = 0usize;
    let mut worlds_with_contests = 0usize;
    for _ in 0..1500 {
        let mut w = random_world(&mut rng);
        if !contests(&project_tree(&w.state.heads, kind_of)).is_empty() {
            worlds_with_contests += 1;
        }
        let versions_before = live_versions(&w.state);
        // Take turns until no author has anything to move.
        for round in 0.. {
            assert!(round < 12, "forks did not terminate");
            let mut any = false;
            for name in ["a", "b", "c"] {
                let limits = ForkLimits {
                    max_ops_per_delta: 3 + rng.below(6),
                    max_bytes_per_delta: usize::MAX,
                };
                let plan = match plan_own_forks(&w.state, &author(name), kind_of, limits) {
                    Ok(plan) => plan,
                    Err(ForkError::BucketFull { .. }) => continue,
                    Err(other) => panic!("{other}"),
                };
                for delta in &plan.deltas {
                    assert_self_contained(delta);
                    assert!(delta.ops.len() <= limits.max_ops_per_delta);
                    assert_removes_only_own_heads(delta, &author(name));
                }
                if !plan.deltas.is_empty() {
                    any = true;
                    planned_deltas += plan.deltas.len();
                    w.apply(name, &plan);
                }
            }
            // A version present before is still present after every round.
            assert!(live_versions(&w.state).is_superset(&versions_before));
            if !any {
                break;
            }
        }
    }
    assert!(planned_deltas > 300, "{planned_deltas}");
    assert!(worlds_with_contests > 300, "{worlds_with_contests}");
}

#[test]
fn every_removal_in_a_plan_names_a_head_that_is_live_when_its_delta_applies() {
    let mut rng = Rng(0xDEADBEEFCAFEF00D);
    let mut checked = 0usize;
    for _ in 0..800 {
        let w = random_world(&mut rng);
        for name in ["a", "b", "c"] {
            let Ok(plan) = plan_own_forks(
                &w.state,
                &author(name),
                kind_of,
                ForkLimits { max_ops_per_delta: 4, max_bytes_per_delta: usize::MAX },
            ) else {
                continue;
            };
            let mut sim = w.state.clone();
            for delta in &plan.deltas {
                let put_versions: BTreeSet<VersionHash> = delta
                    .ops
                    .iter()
                    .filter_map(|op| op.put.as_ref().map(|put| put.version))
                    .collect();
                for op in &delta.ops {
                    for removal in &op.removes {
                        let head = sim.heads.get(&op.path).and_then(|h| h.get(&removal.dot));
                        assert_eq!(
                            head.map(|payload| payload.provenance),
                            Some(removal.provenance),
                            "a removal names a head that is not live"
                        );
                        // No delta removes a head of a version it does not put.
                        assert!(put_versions.contains(&head.unwrap().version));
                        checked += 1;
                    }
                }
                let single = ForkPlan {
                    deltas: vec![delta.clone()],
                    waiting_for_records: vec![],
                    refused: vec![],
                };
                apply_plan(&mut sim, &author(name), &single);
            }
        }
    }
    assert!(checked > 300, "{checked}");
}

/// The previous native copy name and the new one differ in exactly the ways
/// the design changes: no label, an id over the full path and version, and no
/// stripping of an existing marker.
#[test]
fn the_new_copy_name_differs_from_the_previous_one_in_label_id_and_stripping() {
    use crate::conflict::native_copy_path;
    let version = v(7);
    let old = native_copy_path("dir/a.txt", "laptop", &version.0);
    let new = copy_path("dir/a.txt", &version);
    assert!(old.contains("laptop"));
    assert!(!new.contains("laptop"));
    assert_ne!(old, new);
    // The previous name stripped a marker (a copy of a copy kept one suffix);
    // the new one does not.
    let old_of_copy = native_copy_path(&old, "laptop", &version.0);
    assert_eq!(old_of_copy.matches("(conflicted copy, ").count(), 1);
    assert_eq!(copy_path(&new, &version).matches("(conflicted copy, ").count(), 2);
}

// --- fallback by another Writer ----------------------------------------

/// A group's verified policy chain as the fold of its grant and revoke
/// records, so two replicas holding the same chain up to the same point
/// compute the same writer set, and an older point is simply an older set.
#[derive(Clone, Copy)]
enum PolicyEvent {
    Grant(&'static str),
    Revoke(&'static str),
}

fn writer_at(chain: &[PolicyEvent], seq: usize, device: &str) -> bool {
    let mut writers: BTreeSet<&str> = BTreeSet::new();
    for event in &chain[..seq] {
        match event {
            PolicyEvent::Grant(d) => writers.insert(d),
            PolicyEvent::Revoke(d) => writers.remove(d),
        };
    }
    writers.contains(device)
}

#[test]
fn fallback_eligibility_is_a_function_of_the_closed_state_and_the_policy_point_only() {
    assert!(fallback_may_fork(true, true), "a closed author never acts again");
    assert!(fallback_may_fork(true, false));
    assert!(fallback_may_fork(false, false), "a device that is not a writer cannot fork");
    assert!(!fallback_may_fork(false, true), "an open writer forks its own heads");

    let chain = [PolicyEvent::Grant("a"), PolicyEvent::Grant("w"), PolicyEvent::Revoke("a")];
    // The same verified chain up to the same point answers the same, however
    // often and wherever it is folded.
    for seq in 0..=chain.len() {
        assert_eq!(writer_at(&chain, seq, "a"), writer_at(&chain.clone(), seq, "a"));
    }
    // A replica that has not yet seen the revocation answers "not yet": the
    // lag only delays the fallback.
    assert!(!fallback_may_fork(false, writer_at(&chain, 2, "a")));
    assert!(fallback_may_fork(false, writer_at(&chain, 3, "a")));
}

#[test]
fn a_fallback_writer_removes_only_the_owners_heads_and_puts_under_its_own_dot() {
    let mut w = World::new();
    let owner_head = w.put("a", "f", 1);
    let winner = w.put("b", "f", 2);
    let bystander = w.put("c", "g", 5);
    let plan = plan_forks(&w.state, &author("a"), &author("w"), kind_of, LIMITS).unwrap();
    assert_eq!(plan.deltas.len(), 1);
    for removal in plan.deltas[0].ops.iter().flat_map(|op| op.removes.iter()) {
        assert_eq!(removal.dot, owner_head);
    }
    apply_plan(&mut w.state, &author("w"), &plan);
    let at_f: Vec<&Dot> = w.state.heads[&p("f")].keys().collect();
    assert_eq!(at_f, vec![&winner]);
    let copy = &w.state.heads[&p(&copy_path("f", &v(1)))];
    assert!(copy.keys().all(|dot| dot.author == author("w")));
    assert!(w.state.heads[&p("g")].contains_key(&bystander));
    // The owner has nothing left to move.
    assert_eq!(w.plan("a"), ForkPlan::default());
}

struct Fallback {
    base: NativeState,
    /// Deltas by name, each signed against the base (concurrent with the
    /// others), ready to be admitted in any order.
    deltas: Vec<(AuthorId, AuthorSeq, Vec<RemoteOp>)>,
}

fn fallback_scenario(signers: &[&str], owner_forks_late: bool) -> Fallback {
    let mut w = World::new();
    w.put("a", "f", 1);
    w.put("b", "f", 2);
    let base = w.state.clone();
    let mut deltas = Vec::new();
    for signer in signers {
        let plan = plan_forks(&base, &author("a"), &author(signer), kind_of, LIMITS).unwrap();
        assert_eq!(plan.deltas.len(), 1);
        let seq = base.next_dot(&author(signer)).unwrap().seq;
        deltas.push((author(signer), seq, remote_ops(&plan.deltas[0], &author(signer), seq)));
    }
    if owner_forks_late {
        // The revoked-then-regranted owner publishes its own stale fork of
        // the same head from its old chain.
        let plan = plan_own_forks(&base, &author("a"), kind_of, LIMITS).unwrap();
        let seq = base.next_dot(&author("a")).unwrap().seq;
        deltas.push((author("a"), seq, remote_ops(&plan.deltas[0], &author("a"), seq)));
    }
    Fallback { base, deltas }
}

fn admit(
    base: &NativeState,
    deltas: &[(AuthorId, AuthorSeq, Vec<RemoteOp>)],
    order: &[usize],
) -> NativeState {
    let mut state = base.clone();
    for &i in order {
        let (signer, seq, ops) = &deltas[i];
        state.receive_verified(signer, *seq, ops).unwrap();
    }
    state.check_invariants().unwrap();
    state
}

fn orders(n: usize) -> Vec<Vec<usize>> {
    fn go(prefix: &mut Vec<usize>, out: &mut Vec<Vec<usize>>, n: usize) {
        if prefix.len() == n {
            out.push(prefix.clone());
            return;
        }
        for i in 0..n {
            if !prefix.contains(&i) {
                prefix.push(i);
                go(prefix, out, n);
                prefix.pop();
            }
        }
    }
    let mut out = Vec::new();
    go(&mut Vec::new(), &mut out, n);
    out
}

/// Replicas with different policy lag may or may not have forked: two
/// Writers and the late owner all sign the same rename. In every arrival
/// order the state is the same, the loser's version is live at the copy
/// path, the contested path holds only the winner, and nothing was dropped.
#[test]
fn concurrent_fallback_forks_and_a_late_owner_fork_converge_without_loss() {
    for signers in [&["w1"][..], &["w1", "w2"][..]] {
        for owner_late in [false, true] {
            let scenario = fallback_scenario(signers, owner_late);
            let n = scenario.deltas.len();
            let copy = p(&copy_path("f", &v(1)));
            let mut seen: Option<NativeState> = None;
            for order in orders(n) {
                let state = admit(&scenario.base, &scenario.deltas, &order);
                match &seen {
                    Some(first) => assert_eq!(&state, first, "order {order:?}"),
                    None => seen = Some(state.clone()),
                }
                assert!(state
                    .heads
                    .get(&copy)
                    .is_some_and(|h| h.values().all(|x| x.version == v(1))));
                assert_eq!(state.heads[&p("f")].len(), 1, "only the winner holds the path");
                assert!(
                    live_versions(&state).contains(&v(1)) && live_versions(&state).contains(&v(2))
                );
                let tree = project_tree(&state.heads, kind_of);
                assert!(contests(&tree).is_empty());
                // One visible class at the copy path.
                assert!(matches!(tree[&copy], crate::native_project::Projection::Settled(_)));
            }
        }
    }
}

/// The accepted behaviour of the fallback path: a user deletes the copy after
/// the first fork, and a second fork signed concurrently arrives later. Its
/// put carries a dot the delete did not observe, so the copy shows again. The
/// state is the same in every order and the version is never lost.
#[test]
fn a_second_fallback_fork_after_a_user_delete_reappears_and_converges() {
    let scenario = fallback_scenario(&["w1", "w2"], false);
    let copy = p(&copy_path("f", &v(1)));
    let mut with_w1 = scenario.base.clone();
    let (s1, q1, ops1) = &scenario.deltas[0];
    with_w1.receive_verified(s1, *q1, ops1).unwrap();
    let observed: Vec<Dot> = with_w1.heads[&copy].keys().cloned().collect();
    // The user (author u) deletes what they saw: only W1's head.
    let delete_state = with_w1.clone();
    let user = author("u");
    let delete_seq = delete_state.next_dot(&user).unwrap().seq;
    let delete_ops = vec![RemoteOp {
        path: copy.clone(),
        removes: observed
            .iter()
            .map(|dot| HeadRef {
                dot: dot.clone(),
                provenance: with_w1.heads[&copy][dot].provenance,
            })
            .collect(),
        put: None,
    }];
    let (s2, q2, ops2) = &scenario.deltas[1];
    let mut results = Vec::new();
    for order in [[0usize, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        // Index 2 is the user's delete; it can only follow W1's put it saw.
        let pos = |i: usize| order.iter().position(|&x| x == i).unwrap();
        if pos(0) > pos(2) {
            continue;
        }
        let mut state = scenario.base.clone();
        for i in order {
            match i {
                0 => state.receive_verified(s1, *q1, ops1).unwrap(),
                1 => state.receive_verified(s2, *q2, ops2).unwrap(),
                _ => state.receive_verified(&user, delete_seq, &delete_ops).unwrap(),
            };
        }
        state.check_invariants().unwrap();
        assert!(live_versions(&state).contains(&v(1)), "the loser's version is never lost");
        assert!(state.heads.contains_key(&copy), "the copy shows again from W2's put");
        results.push(state);
    }
    assert!(results.len() >= 2);
    assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
}

/// A closed author is no different from a revoked one: the fork a Writer
/// signs for it is the same ordinary delta, and the closed author, which can
/// never publish again, cannot add a stale duplicate.
#[test]
fn a_closed_author_is_forked_for_by_one_writer_and_stays_settled() {
    let scenario = fallback_scenario(&["w1"], false);
    let state = admit(&scenario.base, &scenario.deltas, &[0]);
    assert!(contests(&project_tree(&state.heads, kind_of)).is_empty());
    assert_eq!(
        plan_forks(&state, &author("a"), &author("w1"), kind_of, LIMITS).unwrap(),
        ForkPlan::default()
    );
}

// --- same content, different version ----------------------------------------

/// Versions are `[1, content, time, 0...]`: versions that differ only in the
/// third byte hold the same content.
fn cv(content: u8, time: u8) -> VersionHash {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes[1] = content;
    bytes[2] = time;
    VersionHash(bytes)
}

fn content_info(version: &VersionHash) -> Option<VersionInfo> {
    Some(VersionInfo {
        kind: RecordKind::File,
        content: Some(crate::ids::ContentIdentity([version.0[1]; 32])),
    })
}

fn kind_only(version: &VersionHash) -> Option<RecordKind> {
    content_info(version).map(|info| info.kind)
}

fn put_version(world: &mut World, name: &str, path: &str, version: VersionHash) {
    let provenance = DeltaHash([world.next_provenance; 32]);
    world.next_provenance = world.next_provenance.wrapping_add(1).max(1);
    world.state.put(&author(name), p(path), &[], HeadPayload { version, provenance }).unwrap();
}

fn plan_for(world: &World, name: &str) -> ForkPlan {
    plan_own_forks(&world.state, &author(name), content_info, LIMITS).unwrap()
}

fn versions_at(world: &World, path: &str) -> Vec<(String, VersionHash)> {
    let mut got: Vec<_> = world
        .state
        .heads_at(&p(path))
        .map(|h| (h.dot.author.device.0.clone(), h.payload.version))
        .collect();
    got.sort();
    got
}

fn settle(world: &mut World, names: &[&str]) {
    for _ in 0..8 {
        let mut moved = false;
        for name in names {
            let plan = plan_for(world, name);
            moved |= !plan.deltas.is_empty();
            apply_plan(&mut world.state, &author(name), &plan);
        }
        if !moved {
            return;
        }
    }
    panic!("did not settle");
}

#[test]
fn the_author_of_the_smaller_version_of_one_content_adopts_the_larger() {
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "b", "f", cv(7, 9));

    assert!(
        plan_for(&world, "b").deltas.is_empty(),
        "the author of the largest version has nothing to move"
    );

    let plan = plan_for(&world, "a");
    assert_eq!(plan.deltas.len(), 1);
    let ops = &plan.deltas[0].ops;
    assert_eq!(ops.len(), 1, "a replacement at the same path, no copy");
    assert_eq!(ops[0].path, p("f"));
    assert_eq!(ops[0].removes.len(), 1);
    assert_eq!(ops[0].put.as_ref().map(|put| put.version), Some(cv(7, 9)));

    apply_plan(&mut world.state, &author("a"), &plan);
    assert!(contests(&project_tree(&world.state.heads, kind_only)).is_empty());
    assert_eq!(
        versions_at(&world, "f"),
        [("a".into(), cv(7, 9)), ("b".into(), cv(7, 9))],
        "both authors' heads are kept"
    );
    assert!(plan_for(&world, "a").deltas.is_empty() && plan_for(&world, "b").deltas.is_empty());
    assert_eq!(world.state.heads.len(), 1, "no conflicted copy");
}

#[test]
fn adoption_does_not_depend_on_who_plans_first() {
    for order in [["a", "b", "c"], ["c", "b", "a"], ["b", "a", "c"]] {
        let mut world = World::new();
        put_version(&mut world, "a", "f", cv(7, 1));
        put_version(&mut world, "b", "f", cv(7, 9));
        put_version(&mut world, "c", "f", cv(7, 5));
        settle(&mut world, &order);
        assert_eq!(world.state.heads.len(), 1, "{order:?}");
        let got = versions_at(&world, "f");
        assert_eq!(got.len(), 3, "{order:?}");
        assert!(got.iter().all(|(_, v)| *v == cv(7, 9)), "{order:?}: {got:?}");
    }
}

#[test]
fn a_difference_beyond_time_is_not_adopted() {
    // Different content: the usual fork, nothing replaced in place.
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "b", "f", cv(8, 1));
    let plan = plan_for(&world, "a");
    assert_eq!(plan.deltas.len(), 1);
    assert!(plan.deltas[0].ops.iter().all(|op| op.path != p("f") || op.put.is_none()));
    assert!(plan.deltas[0].ops.iter().any(|op| op.path.as_str().contains("conflicted copy")));

    // Versions whose content is not known are their own content.
    let mut world = World::new();
    put_version(&mut world, "a", "f", v(5));
    put_version(&mut world, "b", "f", v(6));
    let plan = plan_own_forks(&world.state, &author("a"), kind_of, LIMITS).unwrap();
    assert!(plan.deltas[0].ops.iter().any(|op| op.path.as_str().contains("conflicted copy")));
}

#[test]
fn two_authors_of_one_losing_content_end_with_one_copy() {
    // Content 7 (written at two times) loses to content 8: the two authors
    // first agree on a version, then move it to the same copy path.
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "b", "f", cv(7, 9));
    put_version(&mut world, "c", "f", cv(8, 1));
    settle(&mut world, &["a", "b", "c"]);

    let tree = project_tree(&world.state.heads, kind_only);
    assert!(contests(&tree).is_empty(), "{:?}", contests(&tree));
    let copy = copy_path("f", &cv(7, 9));
    let paths: BTreeSet<String> = world.state.heads.keys().map(|k| k.as_str().to_owned()).collect();
    assert_eq!(paths, BTreeSet::from(["f".to_owned(), copy.clone()]));
    assert_eq!(versions_at(&world, "f"), [("c".to_owned(), cv(8, 1))], "the winner is untouched");
    assert_eq!(versions_at(&world, &copy), [("a".into(), cv(7, 9)), ("b".into(), cv(7, 9))]);
}

#[test]
fn a_head_waits_for_a_missing_record_instead_of_adopting() {
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "b", "f", v(0xFF));
    let info =
        |version: &VersionHash| (version.0[0] != 0xFF).then(|| content_info(version)).flatten();
    let plan = plan_own_forks(&world.state, &author("a"), info, LIMITS).unwrap();
    assert_eq!(plan.waiting_for_records, [p("f")]);
    assert!(plan.deltas.is_empty());
}

#[test]
fn an_author_holding_two_contents_replaces_only_the_smaller_version_of_one() {
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "a", "f", cv(8, 1));
    put_version(&mut world, "b", "f", cv(7, 9));
    let plan = plan_for(&world, "a");
    apply_plan(&mut world.state, &author("a"), &plan);
    world.state.check_invariants().unwrap();
    let got = versions_at(&world, "f");
    assert!(got.contains(&("a".into(), cv(8, 1))), "{got:?}");
    assert!(got.contains(&("a".into(), cv(7, 9))), "{got:?}");
    assert!(!got.contains(&("a".into(), cv(7, 1))), "{got:?}");
}

#[test]
fn random_contents_at_random_times_settle_without_losing_a_content() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let mut adopted = 0usize;
    for _ in 0..1500 {
        let mut w = World::new();
        let paths = ["p", "q"];
        for name in ["a", "b", "c"] {
            for path in paths {
                for _ in 0..rng.below(3) {
                    let version = cv(1 + rng.below(3) as u8, 1 + rng.below(3) as u8);
                    put_version(&mut w, name, path, version);
                }
            }
        }
        let contents_before: BTreeSet<(SyncPath, u8)> = w
            .state
            .heads
            .iter()
            .flat_map(|(path, heads)| heads.values().map(move |h| (path.clone(), h.version.0[1])))
            .collect();
        let mut order = ["a", "b", "c"];
        for round in 0.. {
            assert!(round < 16, "did not terminate");
            // A different turn order every round.
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i + 1));
            }
            let mut any = false;
            for name in order {
                let plan = match plan_own_forks(&w.state, &author(name), content_info, LIMITS) {
                    Ok(plan) => plan,
                    Err(ForkError::BucketFull { .. }) => continue,
                    Err(other) => panic!("{other}"),
                };
                for delta in &plan.deltas {
                    // A removal without a put is a replaced version whose content
                    // the author's own larger version already holds.
                    let paths: BTreeSet<_> = delta.ops.iter().map(|op| &op.path).collect();
                    assert_eq!(paths.len(), delta.ops.len(), "duplicate path in one delta");
                    assert_removes_only_own_heads(delta, &author(name));
                    adopted += delta
                        .ops
                        .iter()
                        .filter(|op| op.put.is_some() && op.path.as_str() == "p")
                        .count();
                }
                if !plan.deltas.is_empty() {
                    any = true;
                    w.apply(name, &plan);
                }
            }
            if !any {
                break;
            }
        }
        // Nothing is contested between distinct contents once every author
        // has moved, except where a bucket was full; and no content that was
        // live at a path is gone from the tree.
        let contents_after: BTreeSet<u8> = w
            .state
            .heads
            .values()
            .flat_map(|heads| heads.values().map(|h| h.version.0[1]))
            .collect();
        for (_, content) in &contents_before {
            assert!(contents_after.contains(content), "content {content} lost");
        }
        let tree = project_tree(&w.state.heads, kind_only);
        for contest in contests(&tree) {
            // A remaining contest is between versions of different content,
            // or its author could not move (full bucket).
            let heads = &w.state.heads[&contest.path];
            let distinct: BTreeSet<VersionHash> = heads.values().map(|h| h.version).collect();
            assert!(distinct.len() > 1, "{contest:?}");
        }
    }
    assert!(adopted > 200, "{adopted}");
}

#[test]
fn a_fallback_signer_without_room_to_adopt_copies_the_losing_heads_instead() {
    // The owner holds two times of a losing content; the signer's own two
    // heads at the path are of other versions, so it cannot put the adopted
    // version there. The losing heads must still move to their copies.
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "a", "f", cv(7, 2));
    put_version(&mut world, "w", "f", cv(9, 1));
    put_version(&mut world, "w", "f", cv(9, 2));
    let plan = plan_forks(&world.state, &author("a"), &author("w"), content_info, LIMITS).unwrap();
    assert!(plan.refused.is_empty(), "{:?}", plan.refused);
    assert!(!plan.deltas.is_empty());
    apply_plan(&mut world.state, &author("w"), &plan);
    world.state.check_invariants().unwrap();
    let remaining: Vec<_> = versions_at(&world, "f");
    assert!(remaining.iter().all(|(who, _)| who != "a"), "{remaining:?}");
    let contents: BTreeSet<u8> = world
        .state
        .heads
        .values()
        .flat_map(|heads| heads.values().map(|h| h.version.0[1]))
        .collect();
    assert!(contents.contains(&7), "the owner's content survives at a copy");
}

#[test]
fn a_copy_is_not_planned_onto_a_path_the_same_plan_replaces_in_place() {
    // `f` loses to content 9, so its content-7 head is copied to the copy path
    // of v(7, 9); that copy path itself holds two times of content 5 of the
    // same author, one of which has to be replaced first.
    let copy = copy_path("f", &cv(7, 9));
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 9));
    put_version(&mut world, "b", "f", cv(9, 1));
    put_version(&mut world, "a", &copy, cv(5, 1));
    put_version(&mut world, "c", &copy, cv(5, 2));
    let plan = plan_for(&world, "a");
    for delta in &plan.deltas {
        let adopts = delta.ops.iter().any(|op| op.path.as_str() == copy && op.put.is_some());
        assert!(!(adopts && delta.ops.iter().any(|op| op.path.as_str() == "f")), "{delta:?}");
    }
    // Planning again after applying it finishes the job.
    settle(&mut world, &["a", "b", "c"]);
    assert!(contests(&project_tree(&world.state.heads, kind_only)).is_empty());
}

#[test]
fn adoption_always_leaves_a_fresh_head_so_a_concurrent_delete_cannot_end_the_write() {
    // `a` holds both times of one content. Replacing the smaller must put a
    // new head of the larger rather than only remove: a replica that saw just
    // the old larger head can delete it concurrently.
    let mut world = World::new();
    put_version(&mut world, "a", "f", cv(7, 1));
    put_version(&mut world, "a", "f", cv(7, 9));
    let old_larger =
        world.state.heads_at(&p("f")).find(|h| h.payload.version == cv(7, 9)).unwrap().dot.clone();
    let plan = plan_for(&world, "a");
    let op = &plan.deltas[0].ops[0];
    assert_eq!(op.put.as_ref().map(|put| put.version), Some(cv(7, 9)));
    assert_eq!(op.removes.len(), 1, "only the smaller version is removed while there is room");

    apply_plan(&mut world.state, &author("a"), &plan);
    // A delete that observed only the old larger head, merged afterwards.
    world.state.delete(&author("r"), p("f"), &[old_larger]).unwrap();
    assert_eq!(
        world.state.heads_at(&p("f")).map(|h| h.payload.version).collect::<Vec<_>>(),
        [cv(7, 9)],
        "the fresh head survives the delete"
    );
}
