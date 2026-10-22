use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::author::{AuthorId, IncarnationId};
use crate::ids::{AuthorSeq, DeltaHash, DeviceId};
use crate::native_state::{HeadPayload, NativeState, RemoteOp};
use crate::signed_delta::HeadRef;

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_owned()), incarnation: IncarnationId([1u8; 16]) }
}

fn v(byte: u8) -> VersionHash {
    VersionHash([byte; 32])
}

/// Versions 0xD0..=0xDF are directories, 0xE0..=0xEF symlinks, 0xFF has no
/// record yet, everything else is a file.
fn kind_of(version: &VersionHash) -> Option<RecordKind> {
    match version.0[0] {
        0xD0..=0xDF => Some(RecordKind::Directory),
        0xE0..=0xEF => Some(RecordKind::Symlink),
        0xFF => None,
        _ => Some(RecordKind::File),
    }
}

fn head(name: &str, seq: u64, version: u8) -> LiveHead {
    LiveHead {
        dot: Dot { author: author(name), seq: AuthorSeq(seq) },
        payload: HeadPayload { version: v(version), provenance: DeltaHash([seq as u8; 32]) },
    }
}

fn project(heads: Vec<LiveHead>, descendant: bool) -> Projection {
    project_path(heads, kind_of, descendant)
}

#[test]
fn project_path_table() {
    use PendingReason::*;
    let entry = |kind, version: u8, name: &str, seq| {
        Projection::Settled(Settled::Entry {
            kind,
            version: v(version),
            representative: Dot { author: author(name), seq: AuthorSeq(seq) },
        })
    };
    let explicit = |version: u8| {
        Projection::Settled(Settled::Directory(DirectoryNode::Explicit { version: v(version) }))
    };
    let structural = Projection::Settled(Settled::Directory(DirectoryNode::Structural));

    let cases: Vec<(&str, Vec<LiveHead>, bool, Projection)> = vec![
        ("nothing", vec![], false, Projection::Absent),
        ("descendant only", vec![], true, structural.clone()),
        ("lone file", vec![head("a", 1, 1)], false, entry(RecordKind::File, 1, "a", 1)),
        ("lone symlink", vec![head("a", 1, 0xE1)], false, entry(RecordKind::Symlink, 0xE1, "a", 1)),
        // Equal versions are one class; the larger provenance represents it.
        (
            "equal versions collapse",
            vec![head("a", 1, 5), head("b", 3, 5)],
            false,
            entry(RecordKind::File, 5, "b", 3),
        ),
        (
            "file and file",
            vec![head("a", 1, 1), head("b", 1, 2)],
            false,
            Projection::Pending(DistinctVersions),
        ),
        (
            "file and symlink",
            vec![head("a", 1, 1), head("b", 1, 0xE1)],
            false,
            Projection::Pending(DistinctVersions),
        ),
        (
            "file and directory",
            vec![head("a", 1, 9), head("b", 1, 0xD1)],
            false,
            Projection::Pending(DirectoryRequired),
        ),
        (
            "file with live descendant",
            vec![head("a", 1, 9)],
            true,
            Projection::Pending(DirectoryRequired),
        ),
        (
            "file, directory and descendant",
            vec![head("a", 1, 9), head("b", 1, 0xD1)],
            true,
            Projection::Pending(DirectoryRequired),
        ),
        ("directory alone", vec![head("a", 1, 0xD1)], false, explicit(0xD1)),
        ("directory with descendant", vec![head("a", 1, 0xD1)], true, explicit(0xD1)),
        (
            "directory and directory is no contest",
            vec![head("a", 1, 0xD1), head("b", 1, 0xD7)],
            false,
            explicit(0xD7),
        ),
        (
            "missing record",
            vec![head("a", 1, 0xFF)],
            false,
            Projection::Pending(UnknownKind { version: v(0xFF) }),
        ),
        (
            "missing record next to a directory",
            vec![head("a", 1, 0xD1), head("b", 1, 0xFF)],
            false,
            Projection::Pending(UnknownKind { version: v(0xFF) }),
        ),
    ];
    for (name, heads, descendant, expected) in cases {
        assert_eq!(project(heads, descendant), expected, "{name}");
    }
}

#[test]
fn the_projection_of_a_path_ignores_the_order_of_its_heads() {
    let all = vec![head("a", 1, 1), head("b", 2, 2), head("c", 3, 0xD1), head("d", 4, 5)];
    for descendant in [false, true] {
        let expected = project(all.clone(), descendant);
        let mut reversed = all.clone();
        reversed.reverse();
        assert_eq!(project(reversed, descendant), expected);
        let mut rotated = all.clone();
        rotated.rotate_left(2);
        assert_eq!(project(rotated, descendant), expected);
    }
}

/// What the projection did before contested paths became `Pending`, and what
/// it does now, for each shape of contest. The previous resolver showed a
/// winner at the name and placed every other version at a derived copy
/// name, or displaced a file that had to give way to a directory; it could
/// not decide a path whose record was missing. Now such a path is `Pending`
/// until the loser's author renames its head; every uncontested path is
/// unchanged. The table is the record of that difference.
#[test]
fn contested_shapes_are_pending_and_every_other_shape_is_unchanged() {
    use PendingReason::*;
    struct Case {
        shape: &'static str,
        heads: Vec<LiveHead>,
        descendant: bool,
        now: Projection,
        before: &'static str,
    }
    let entry = |version: u8, name: &str, seq| {
        Projection::Settled(Settled::Entry {
            kind: RecordKind::File,
            version: v(version),
            representative: Dot { author: author(name), seq: AuthorSeq(seq) },
        })
    };
    let cases = vec![
        Case {
            shape: "empty",
            heads: vec![],
            descendant: false,
            now: Projection::Absent,
            before: "absent",
        },
        Case {
            shape: "one file",
            heads: vec![head("a", 1, 1)],
            descendant: false,
            now: entry(1, "a", 1),
            before: "the entry at its name",
        },
        Case {
            shape: "equal versions of two authors",
            heads: vec![head("a", 1, 1), head("b", 2, 1)],
            descendant: false,
            now: entry(1, "b", 2),
            before: "the entry at its name, no copy",
        },
        Case {
            shape: "two file versions",
            heads: vec![head("a", 1, 1), head("b", 1, 2)],
            descendant: false,
            now: Projection::Pending(DistinctVersions),
            before: "the larger version at the name and a copy placement for the other",
        },
        Case {
            shape: "file and directory",
            heads: vec![head("a", 1, 9), head("b", 1, 0xD1)],
            descendant: false,
            now: Projection::Pending(DirectoryRequired),
            before: "the directory, the file displaced to a derived name",
        },
        Case {
            shape: "file with a live descendant",
            heads: vec![head("a", 1, 9)],
            descendant: true,
            now: Projection::Pending(DirectoryRequired),
            before: "a structural directory, the file displaced to a derived name",
        },
        Case {
            shape: "record missing",
            heads: vec![head("a", 1, 0xFF)],
            descendant: false,
            now: Projection::Pending(UnknownKind { version: v(0xFF) }),
            before: "refused as undecidable",
        },
        Case {
            shape: "two directory versions",
            heads: vec![head("a", 1, 0xD1), head("b", 1, 0xD7)],
            descendant: false,
            now: Projection::Settled(Settled::Directory(DirectoryNode::Explicit {
                version: v(0xD7),
            })),
            before: "the larger directory version, no copy",
        },
    ];
    for case in cases {
        assert_eq!(
            project(case.heads, case.descendant),
            case.now,
            "{} (before: {})",
            case.shape,
            case.before
        );
    }
}

fn ops_state(deltas: &[(&str, u64, Vec<RemoteOp>)], order: &[usize]) -> NativeState {
    let mut state = NativeState::new();
    for &index in order {
        let (name, seq, ops) = &deltas[index];
        state.receive_verified(&author(name), AuthorSeq(*seq), ops).unwrap();
    }
    state
}

fn put(path: &str, version: u8, provenance: u8) -> RemoteOp {
    RemoteOp {
        path: SyncPath(path.to_owned()),
        removes: vec![],
        put: Some(HeadPayload { version: v(version), provenance: DeltaHash([provenance; 32]) }),
    }
}

fn remove(path: &str, name: &str, seq: u64, provenance: u8) -> RemoteOp {
    RemoteOp {
        path: SyncPath(path.to_owned()),
        removes: vec![HeadRef {
            dot: Dot { author: author(name), seq: AuthorSeq(seq) },
            provenance: DeltaHash([provenance; 32]),
        }],
        put: None,
    }
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn go(prefix: &mut Vec<usize>, used: &mut Vec<bool>, out: &mut Vec<Vec<usize>>) {
        if prefix.len() == used.len() {
            out.push(prefix.clone());
            return;
        }
        for i in 0..used.len() {
            if !used[i] {
                used[i] = true;
                prefix.push(i);
                go(prefix, used, out);
                prefix.pop();
                used[i] = false;
            }
        }
    }
    let mut out = Vec::new();
    go(&mut Vec::new(), &mut vec![false; n], &mut out);
    out
}

/// The same admitted deltas, assembled in every causally valid arrival
/// order, give one head state and one projection, at every prefix set.
#[test]
fn the_projection_is_the_same_for_every_arrival_order_of_the_same_deltas() {
    let deltas: Vec<(&str, u64, Vec<RemoteOp>)> = vec![
        ("a", 1, vec![put("x", 1, 11), put("shared", 7, 12)]), // 0
        ("b", 1, vec![put("x", 2, 21)]),                       // 1
        ("c", 1, vec![put("x/y", 3, 31)]),                     // 2
        ("a", 2, vec![remove("x", "a", 1, 11), put("x (copy)", 1, 41)]), // 3: depends on 0
        ("b", 2, vec![put("d", 0xD1, 51), put("d/e", 4, 52)]), // 4
        ("c", 2, vec![remove("x/y", "c", 1, 31)]),             // 5: depends on 2
    ];
    // (later, earlier) pairs a valid order must respect: own chains and the
    // head a removal names.
    let must_precede = [(3usize, 0usize), (4, 1), (5, 2), (3, 0), (5, 2)];
    let valid = |order: &[usize]| {
        must_precede.iter().all(|(later, earlier)| {
            order.iter().position(|i| i == earlier) < order.iter().position(|i| i == later)
        })
    };

    let mut seen_states: BTreeMap<Vec<usize>, (NativeState, BTreeMap<SyncPath, Projection>)> =
        BTreeMap::new();
    let mut checked = 0usize;
    for order in permutations(deltas.len()).into_iter().filter(|o| valid(o)) {
        // Check every prefix: the state after a set of deltas does not depend
        // on the order inside it.
        for end in 1..=order.len() {
            let mut key: Vec<usize> = order[..end].to_vec();
            key.sort_unstable();
            let state = ops_state(&deltas, &order[..end]);
            let tree = super::project_tree(&state.heads, kind_of);
            match seen_states.get(&key) {
                Some((first_state, first_tree)) => {
                    assert_eq!(&state, first_state, "state differs for set {key:?}");
                    assert_eq!(&tree, first_tree, "projection differs for set {key:?}");
                }
                None => {
                    seen_states.insert(key, (state, tree));
                }
            }
            checked += 1;
        }
    }
    assert!(checked > 400, "{checked}");

    // The full set shows the expected contests: `shared` and `x`'s copy have
    // one version, `d` is a directory with a file child, and `x` is settled
    // once both losers and the descendant are gone.
    let (full_state, full_tree) = seen_states.get(&(0..6).collect::<Vec<_>>()).unwrap();
    full_state.check_invariants().unwrap();
    assert!(matches!(
        full_tree.get(&SyncPath("x".into())),
        Some(Projection::Settled(Settled::Entry { .. }))
    ));
}

#[test]
fn contests_and_blocked_descendants_follow_the_tree() {
    let mut heads: BTreeMap<SyncPath, PathHeads> = BTreeMap::new();
    let mut add = |path: &str, h: LiveHead| {
        heads.entry(SyncPath(path.to_owned())).or_default().insert(h.dot, h.payload);
    };
    add("p", head("a", 1, 1));
    add("p", head("b", 1, 2));
    add("p/child", head("c", 1, 3));
    add("p/dir/leaf", head("c", 2, 4));
    add("q", head("a", 2, 5));
    add("q/z", head("a", 3, 6));
    let tree = project_tree(&heads, kind_of);

    let found: Vec<(String, PendingReason)> =
        contests(&tree).into_iter().map(|c| (c.path.0, c.reason)).collect();
    assert_eq!(
        found,
        vec![
            ("p".to_owned(), PendingReason::DirectoryRequired),
            ("q".to_owned(), PendingReason::DirectoryRequired),
        ]
    );
    let blocked: BTreeSet<String> = blocked_by_pending(&tree).into_iter().map(|p| p.0).collect();
    assert_eq!(
        blocked,
        ["p/child", "p/dir", "p/dir/leaf", "q/z"].into_iter().map(String::from).collect()
    );
    // A sibling whose name only shares a prefix is not below the pending path.
    assert!(!blocked.contains("pq"));
}

#[test]
fn a_sibling_with_a_shared_name_prefix_is_not_a_descendant() {
    let mut heads: BTreeMap<SyncPath, PathHeads> = BTreeMap::new();
    for (path, h) in [("a", head("x", 1, 1)), ("a-b", head("x", 2, 2)), ("a.b", head("x", 3, 3))] {
        heads.entry(SyncPath(path.to_owned())).or_default().insert(h.dot, h.payload);
    }
    let tree = project_tree(&heads, kind_of);
    assert!(tree.values().all(|p| matches!(p, Projection::Settled(Settled::Entry { .. }))));
    assert_eq!(tree.len(), 3);
}

#[test]
fn losing_is_a_function_of_the_heads_at_the_path_and_the_subtree() {
    let mut at_path = PathHeads::new();
    let low = head("a", 1, 1);
    let high = head("b", 1, 2);
    for h in [&low, &high] {
        at_path.insert(h.dot.clone(), h.payload.clone());
    }
    assert_eq!(loses(&low, kind_of, &at_path, false), Some(true));
    assert_eq!(loses(&high, kind_of, &at_path, false), Some(false));
    // A descendant makes every file-like head a loser, the larger one too.
    assert_eq!(loses(&high, kind_of, &at_path, true), Some(true));
    // A directory head never loses; a missing record cannot be judged.
    let dir = head("c", 1, 0xD1);
    let mut with_dir = at_path.clone();
    with_dir.insert(dir.dot.clone(), dir.payload.clone());
    assert_eq!(loses(&dir, kind_of, &with_dir, false), Some(false));
    assert_eq!(loses(&high, kind_of, &with_dir, false), Some(true));
    let unknown = head("d", 1, 0xFF);
    let mut with_unknown = at_path;
    with_unknown.insert(unknown.dot.clone(), unknown.payload.clone());
    assert_eq!(loses(&low, kind_of, &with_unknown, false), None);
}
