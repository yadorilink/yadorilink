//! Laws of the definition, checked on generated histories.

use std::collections::{BTreeMap, BTreeSet};

use yadorilink_dcf_oracle::semantics::{
    heads_at, is_representable, join, joinable, landed_paths, watermarks,
};
use yadorilink_dcf_oracle::{
    conflict_path, generate, heads_of_history, is_future_equivalent, verify_strict,
    verify_strict_safe, AuthorId, Change, ChangeId, Effect, GenConfig, History, Op, Preservation,
    Scenario, StrictViolation, Universe, Version,
};

const SEEDS: std::ops::Range<u64> = 0..120;

fn scenarios() -> impl Iterator<Item = Scenario> {
    let config = GenConfig::default();
    SEEDS.map(move |seed| generate(seed, &config))
}

/// Every path some change of `histories` touches.
fn touched_paths(u: &Universe, histories: &[&History]) -> BTreeSet<String> {
    histories
        .iter()
        .flat_map(|h| h.iter())
        .flat_map(|&id| u.change(id).ops.iter().map(|op| op.path.clone()))
        .collect()
}

#[test]
fn generation_is_deterministic_and_nontrivial() {
    let config = GenConfig::default();
    let a = generate(7, &config);
    let b = generate(7, &config);
    assert_eq!(a.order, b.order);
    assert_eq!(a.replicas, b.replicas);
    let mut deletes = 0;
    let mut multi = 0;
    let mut preserved = 0;
    let mut concurrent = 0;
    for s in scenarios() {
        for c in s.universe.changes() {
            deletes += usize::from(c.ops.iter().any(|op| op.effect == Effect::Delete));
            multi += usize::from(c.ops.len() > 1);
            preserved += usize::from(!c.preservations.is_empty());
        }
        let all = s.all();
        concurrent += heads_of_history(&s.universe, &all).values().filter(|h| h.len() > 1).count();
    }
    assert!(deletes > 0 && multi > 0 && preserved > 0 && concurrent > 0);
}

#[test]
fn generated_histories_are_representable_and_strict() {
    for s in scenarios() {
        assert!(is_representable(&s.universe, &s.all()), "seed {}", s.seed);
        for h in &s.replicas {
            assert!(is_representable(&s.universe, h), "seed {}", s.seed);
        }
        for (&id, pre) in &s.pre_states {
            assert_eq!(verify_strict_safe(&s.universe, pre, s.universe.change(id)), Ok(()));
        }
    }
}

/// Heads land content and belong to the history, also after joins. One
/// author may hold several heads at a path: an author's own current heads
/// need not be in the basis, so the per-author bound is a seal-time rule,
/// not a property of every history.
///
#[test]
fn heads_are_present() {
    for s in scenarios() {
        let mut histories = s.replicas.clone();
        histories.push(s.all());
        for h in &histories {
            for (path, heads) in heads_of_history(&s.universe, h) {
                for x in heads {
                    let c = s.universe.change(x);
                    assert!(h.contains(&x) && c.lands(&path), "seed {}", s.seed);
                }
            }
        }
    }
}

/// Adding a change whose basis is in the history updates each touched path
/// to `(heads \ basis) ∪ {c if it lands}` and leaves the rest alone.
///
#[test]
fn adding_a_change_is_the_step_rule() {
    for s in scenarios() {
        let mut prefix = History::new();
        for &id in &s.order {
            let c = s.universe.change(id);
            let before = heads_of_history(&s.universe, &prefix);
            let mut next = prefix.clone();
            next.insert(id);
            let after = heads_of_history(&s.universe, &next);
            for path in landed_paths(&s.universe, &next) {
                let old = before.get(&path).cloned().unwrap_or_default();
                let expected: BTreeSet<ChangeId> = if c.touched(&path) {
                    let mut kept: BTreeSet<_> =
                        old.into_iter().filter(|&x| !c.in_basis(&path, x)).collect();
                    if c.lands(&path) {
                        kept.insert(id);
                    }
                    kept
                } else {
                    old
                };
                assert_eq!(after.get(&path).cloned().unwrap_or_default(), expected);
            }
            prefix = next;
        }
    }
}

/// The heads of a union: a head of one side survives when the other side
/// also has it as a head or does not contain it.
///
#[test]
fn union_heads_are_the_join_rule() {
    for s in scenarios() {
        let u = &s.universe;
        for a in &s.replicas {
            for b in &s.replicas {
                assert!(joinable(u, a, b));
                let joined = join(a, b);
                for path in touched_paths(u, &[a, b]) {
                    let ha = heads_at(u, a, &path);
                    let hb = heads_at(u, b, &path);
                    let mut expected: BTreeSet<ChangeId> =
                        ha.iter().copied().filter(|x| hb.contains(x) || !b.contains(x)).collect();
                    expected.extend(hb.iter().copied().filter(|x| !a.contains(x)));
                    assert_eq!(heads_at(u, &joined, &path), expected, "seed {}", s.seed);
                }
            }
        }
    }
}

/// Joining with a sub-history changes nothing, and the join of heads is
/// commutative, associative and idempotent.
#[test]
fn join_laws() {
    for s in scenarios() {
        let u = &s.universe;
        let r = &s.replicas;
        for a in r {
            assert!(is_future_equivalent(u, a, a, r));
            assert_eq!(heads_of_history(u, &join(a, &History::new())), heads_of_history(u, a));
            assert_eq!(heads_of_history(u, &join(a, a)), heads_of_history(u, a));
            for b in r {
                let ab = heads_of_history(u, &join(a, b));
                assert_eq!(ab, heads_of_history(u, &join(b, a)));
                if a.is_superset(b) {
                    assert_eq!(ab, heads_of_history(u, a));
                }
                for c in r {
                    assert_eq!(
                        heads_of_history(u, &join(&join(a, b), c)),
                        heads_of_history(u, &join(a, &join(b, c)))
                    );
                }
            }
        }
    }
}

/// Every pre-state head either stays, is consumed as observed, or is
/// re-landed with its version at its conflict path by the change.
///
#[test]
fn strict_safe_changes_lose_no_head_silently() {
    for s in scenarios() {
        let u = &s.universe;
        for (&id, pre) in &s.pre_states {
            let c = u.change(id);
            let mut post = pre.clone();
            post.insert(id);
            for (path, heads) in heads_of_history(u, pre) {
                let post_heads = heads_at(u, &post, &path);
                for x in heads {
                    let preserved =
                        c.preservations.iter().find(|e| e.source_path == path && e.source == x);
                    let ok = match preserved {
                        Some(e) => {
                            heads_at(u, &post, &e.target_path).contains(&id)
                                && c.version_at(&e.target_path) == u.change(x).version_at(&path)
                        }
                        None => post_heads.contains(&x) || c.in_basis(&path, x),
                    };
                    assert!(ok, "seed {}: {x} at {path} lost by {id}", s.seed);
                }
            }
        }
    }
}

fn put(path: &str, v: u64, basis: &[u64]) -> Op {
    Op {
        path: path.to_owned(),
        effect: Effect::Put(Version(v)),
        basis: basis.iter().map(|&b| ChangeId(b)).collect(),
    }
}

fn change(id: u64, author: u32, seq: u64, ops: Vec<Op>) -> Change {
    Change { id: ChangeId(id), author: AuthorId(author), seq, ops, preservations: vec![] }
}

/// The author-side rule rejects each broken clause.
///
#[test]
fn strict_rule_rejects_broken_changes() {
    let mut u = Universe::new();
    u.insert(change(1, 0, 1, vec![put("a", 1, &[])]));
    u.insert(change(2, 1, 1, vec![put("a", 2, &[])]));
    let pre: History = [ChangeId(1), ChangeId(2)].into_iter().collect();

    // Leaving an own head out of the basis is accepted: it stays a head.
    let skip_own = change(3, 0, 2, vec![put("a", 3, &[2])]);
    assert_eq!(verify_strict(&u, &pre, &skip_own), Ok(()));
    let wrong_seq = change(3, 0, 5, vec![put("a", 3, &[1])]);
    assert!(matches!(verify_strict(&u, &pre, &wrong_seq), Err(StrictViolation::SeqNotNext { .. })));
    let stale = change(3, 0, 2, vec![put("b", 3, &[1])]);
    assert!(matches!(
        verify_strict(&u, &pre, &stale),
        Err(StrictViolation::BasisNotCurrentHead { .. })
    ));

    let target = conflict_path("a", ChangeId(2));
    let mut preserve = change(3, 0, 2, vec![put("a", 3, &[1, 2]), put(&target, 2, &[])]);
    preserve.preservations.push(Preservation {
        source_path: "a".into(),
        source: ChangeId(2),
        target_path: target.clone(),
        version: Version(2),
    });
    assert_eq!(verify_strict_safe(&u, &pre, &preserve), Ok(()));
    let mut wrong_version = preserve.clone();
    wrong_version.ops[1].effect = Effect::Put(Version(9));
    assert!(matches!(
        verify_strict_safe(&u, &pre, &wrong_version),
        Err(StrictViolation::PreservationVersionMismatch { .. })
    ));
    let mut wrong_target = preserve.clone();
    wrong_target.preservations[0].target_path = "elsewhere".into();
    assert!(matches!(
        verify_strict_safe(&u, &pre, &wrong_target),
        Err(StrictViolation::PreservationTargetNotCanonical { .. })
    ));
}

/// Watermarks of generated histories are the per-author counts.
#[test]
fn watermarks_count_author_changes() {
    for s in scenarios() {
        let all = s.all();
        let mut counts: BTreeMap<AuthorId, u64> = BTreeMap::new();
        for &id in &all {
            *counts.entry(s.universe.change(id).author).or_default() += 1;
        }
        assert_eq!(watermarks(&s.universe, &all), counts);
    }
}
