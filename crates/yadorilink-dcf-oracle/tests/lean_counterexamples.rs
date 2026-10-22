//! The oracle reproduces the minimal counterexamples that fix what a
//! branch state must carry.

use std::collections::BTreeSet;

use yadorilink_dcf_oracle::semantics::{heads_at, join, watermarks};
use yadorilink_dcf_oracle::{
    heads_of_history, is_future_equivalent, AuthorId, Change, ChangeId, Effect, Heads, History, Op,
    Universe, Version,
};

const ALICE: AuthorId = AuthorId(0);
const BOB: AuthorId = AuthorId(1);

fn op(path: &str, put: Option<u64>, basis: &[u64]) -> Op {
    Op {
        path: path.to_owned(),
        effect: put.map_or(Effect::Delete, |v| Effect::Put(Version(v))),
        basis: basis.iter().map(|&b| ChangeId(b)).collect(),
    }
}

fn change(id: u64, author: AuthorId, seq: u64, ops: Vec<Op>) -> Change {
    Change { id: ChangeId(id), author, seq, ops, preservations: vec![] }
}

fn history(ids: &[u64]) -> History {
    ids.iter().map(|&i| ChangeId(i)).collect()
}

fn set(ids: &[u64]) -> BTreeSet<ChangeId> {
    ids.iter().map(|&i| ChangeId(i)).collect()
}

/// Alice writes `p` (x = 1) and then deletes it (y = 2); Bob does the same
/// at `q` (xq = 3, yq = 4).
fn minimality_universe() -> Universe {
    let mut u = Universe::new();
    u.insert(change(1, ALICE, 1, vec![op("p", Some(1), &[])]));
    u.insert(change(2, ALICE, 2, vec![op("p", None, &[1])]));
    u.insert(change(3, BOB, 1, vec![op("q", Some(3), &[])]));
    u.insert(change(4, BOB, 2, vec![op("q", None, &[3])]));
    u
}

#[test]
fn value_coalescing_unsound() {
    let u = minimality_universe();
    let base = History::new();
    let side_a = history(&[1, 2]);
    let side_b = history(&[1]);

    let base_heads = heads_of_history(&u, &base);
    let a_heads = heads_of_history(&u, &side_a);
    assert_eq!(a_heads, base_heads, "side A is back to the base value");
    assert_eq!(heads_at(&u, &side_b, "p"), set(&[1]));
    assert_eq!(heads_at(&u, &join(&side_a, &side_b), "p"), set(&[]));

    // A patch holding only the paths whose value differs from the base is
    // empty for side A, so merging patches yields side B's value: wrong.
    let value_patch = |heads: &Heads| -> Heads {
        heads
            .iter()
            .filter(|(p, h)| base_heads.get(*p) != Some(*h))
            .map(|(p, h)| (p.clone(), h.clone()))
            .collect()
    };
    let mut coalesced = base_heads.clone();
    coalesced.extend(value_patch(&a_heads));
    coalesced.extend(value_patch(&heads_of_history(&u, &side_b)));
    assert_ne!(coalesced, heads_of_history(&u, &join(&side_a, &side_b)));
}

#[test]
fn watermark_necessary() {
    let u = minimality_universe();
    let base = History::new();
    let wrote_deleted = history(&[1, 2]);
    let kept_write = history(&[1]);

    assert_eq!(heads_of_history(&u, &wrote_deleted), heads_of_history(&u, &base));
    assert_eq!(heads_at(&u, &join(&wrote_deleted, &kept_write), "p"), set(&[]));
    assert_eq!(heads_at(&u, &join(&base, &kept_write), "p"), set(&[1]));
    assert!(!is_future_equivalent(&u, &wrote_deleted, &base, &[kept_write]));
    assert_ne!(watermarks(&u, &wrote_deleted), watermarks(&u, &base));
}

#[test]
fn touch_bits_not_information() {
    // Two branches in which Alice wrote and deleted one entry: at `p`
    // (x = 1, y = 2) or, with different changes at the same dots, at `q`
    // (u = 5, v = 6). Bob's changes are possible third branches.
    let mut u = Universe::new();
    u.insert(change(1, ALICE, 1, vec![op("p", Some(1), &[])]));
    u.insert(change(2, ALICE, 2, vec![op("p", None, &[1])]));
    u.insert(change(5, ALICE, 1, vec![op("q", Some(5), &[])]));
    u.insert(change(6, ALICE, 2, vec![op("q", None, &[5])]));
    u.insert(change(10, BOB, 1, vec![op("p", Some(10), &[])]));
    u.insert(change(11, BOB, 2, vec![op("q", Some(11), &[]), op("p", Some(12), &[10])]));
    u.insert(change(12, BOB, 3, vec![op("q", None, &[11])]));
    let at_p = history(&[1, 2]);
    let at_q = history(&[5, 6]);

    assert_eq!(watermarks(&u, &at_p), watermarks(&u, &at_q));
    assert_eq!(heads_of_history(&u, &at_p), heads_of_history(&u, &at_q));
    let thirds: Vec<History> = [
        &[][..],
        &[10],
        &[10, 11],
        &[10, 11, 12],
        // Fork with one side: skipped, the join is undefined there.
        &[1],
        &[5, 6],
    ]
    .iter()
    .map(|ids| history(ids))
    .collect();
    assert!(is_future_equivalent(&u, &at_p, &at_q, &thirds));
    assert!(u.change(ChangeId(1)).touched("p"));
    assert!(!u.change(ChangeId(5)).touched("p"));
    assert!(!u.change(ChangeId(6)).touched("p"));
}

/// Supersession is read from signed bases, so the heads do not depend on
/// the order changes arrive in.
///
#[test]
fn basis_check_needed_heads_are_order_free() {
    let mut u = Universe::new();
    u.insert(change(1, BOB, 1, vec![op("", Some(1), &[])]));
    u.insert(change(2, AuthorId(2), 1, vec![op("", Some(2), &[1])]));
    assert_eq!(heads_at(&u, &history(&[1, 2]), ""), set(&[2]));
    assert_eq!(heads_at(&u, &history(&[2]), ""), set(&[2]));
    assert_eq!(heads_at(&u, &history(&[1]), ""), set(&[1]));
}
