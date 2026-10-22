//! Heads of a history, computed from the definition and nothing else.
//!
//! `y` supersedes `x` at `p` when `y` touches `p` and `x` is in its basis
//! there, or some member of that basis supersedes `x` at `p` (the
//! transitive closure of signed basis edges; DAG ancestry is never read).
//! The heads of a history `H` at `p` are the changes of `H` that land
//! content at `p` and that no change of `H` supersedes at `p`.
//!
//! No state, watermark or transition rule is used: every function here
//! re-derives its answer from the set of changes, so it can serve as the
//! reference against which incremental algorithms are compared.
//!

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{AuthorId, ChangeId, Heads, History, Path, Universe};

/// Whether `y` supersedes `x` at `path` through signed basis edges.
///
/// The intermediate changes of the chain need not be in any particular
/// history; a basis member missing from the universe touches nothing.
///
pub fn supersedes(universe: &Universe, path: &str, x: ChangeId, y: ChangeId) -> bool {
    let mut visited = BTreeSet::new();
    supersedes_from(universe, path, x, y, &mut visited)
}

fn supersedes_from(
    universe: &Universe,
    path: &str,
    x: ChangeId,
    y: ChangeId,
    visited: &mut BTreeSet<ChangeId>,
) -> bool {
    let Some(change) = universe.get(y) else { return false };
    // Both constructors require the superseder to touch the path.
    if !change.touched(path) {
        return false;
    }
    // `edge`: x is in y's basis at the path.
    if change.in_basis(path, x) {
        return true;
    }
    if !visited.insert(y) {
        return false;
    }
    // `tail`: some basis member b of y at the path supersedes x there.
    change.basis_at(path).any(|b| supersedes_from(universe, path, x, b, visited))
}

/// Whether `x` is a head of `history` at `path`.
///
pub fn is_head(universe: &Universe, history: &History, path: &str, x: ChangeId) -> bool {
    history.contains(&x)
        && universe.get(x).is_some_and(|c| c.lands(path))
        && !history.iter().any(|&y| supersedes(universe, path, x, y))
}

/// The heads of `history` at `path`.
pub fn heads_at(universe: &Universe, history: &History, path: &str) -> BTreeSet<ChangeId> {
    history.iter().copied().filter(|&x| is_head(universe, history, path, x)).collect()
}

/// Every path any change of `history` lands content at.
pub fn landed_paths(universe: &Universe, history: &History) -> BTreeSet<Path> {
    let mut paths = BTreeSet::new();
    for &id in history {
        if let Some(change) = universe.get(id) {
            for op in &change.ops {
                if change.lands(&op.path) {
                    paths.insert(op.path.clone());
                }
            }
        }
    }
    paths
}

/// The heads of `history` at every path that has any.
pub fn heads_of_history(universe: &Universe, history: &History) -> Heads {
    landed_paths(universe, history)
        .into_iter()
        .filter_map(|path| {
            let heads = heads_at(universe, history, &path);
            (!heads.is_empty()).then_some((path, heads))
        })
        .collect()
}

/// Drops empty head sets, so heads maps compare as the Lean predicate does
/// (a path with no heads is the same as an absent path).
pub fn normalize(heads: Heads) -> Heads {
    heads.into_iter().filter(|(_, set)| !set.is_empty()).collect()
}

/// The history of a join: the union of both histories.
pub fn join(left: &History, right: &History) -> History {
    left.union(right).copied().collect()
}

/// Whether no two changes of `history` share an author and a sequence
/// number.
///
pub fn is_fork_free(universe: &Universe, history: &History) -> bool {
    let mut seen = BTreeSet::new();
    history.iter().all(|&id| seen.insert(universe.change(id).dot()))
}

/// Whether every basis member of every change of `history` is in
/// `history`.
///
pub fn is_basis_closed(universe: &Universe, history: &History) -> bool {
    history.iter().all(|&id| {
        universe.change(id).ops.iter().all(|op| op.basis.iter().all(|b| history.contains(b)))
    })
}

/// The highest sequence number of each author in `history`.
///
/// For a history that [`is_representable`], this is the watermark `W` of
/// every state representing it.
pub fn watermarks(universe: &Universe, history: &History) -> BTreeMap<AuthorId, u64> {
    let mut w = BTreeMap::new();
    for &id in history {
        let change = universe.change(id);
        let entry = w.entry(change.author).or_insert(0);
        *entry = (*entry).max(change.seq);
    }
    w
}

/// Whether each author's changes in `history` are exactly the sequence
/// numbers `1..=W`.
fn is_gap_free(universe: &Universe, history: &History) -> bool {
    let mut seqs: BTreeMap<AuthorId, BTreeSet<u64>> = BTreeMap::new();
    for &id in history {
        let change = universe.change(id);
        seqs.entry(change.author).or_default().insert(change.seq);
    }
    seqs.values().all(|s| s.iter().copied().eq(1..=s.len() as u64))
}

/// Whether some state represents `history`: every change is in the
/// universe, each author's sequence numbers are gap-free from 1, there is
/// no author fork, and the history is basis-closed.
///
pub fn is_representable(universe: &Universe, history: &History) -> bool {
    history.iter().all(|&id| universe.get(id).is_some())
        && is_fork_free(universe, history)
        && is_gap_free(universe, history)
        && is_basis_closed(universe, history)
}

/// Whether `left` and `right` may be joined: their union has no author
/// fork.
///
pub fn joinable(universe: &Universe, left: &History, right: &History) -> bool {
    is_fork_free(universe, &join(left, right))
}

/// Whether `x` and `y` give the same heads everywhere when joined with each
/// of `thirds`.
///
/// A third history that forms an author fork with either side is skipped:
/// the join is defined only for fork-free unions.
///
pub fn is_future_equivalent(
    universe: &Universe,
    x: &History,
    y: &History,
    thirds: &[History],
) -> bool {
    thirds
        .iter()
        .filter(|z| joinable(universe, x, z) && joinable(universe, y, z))
        .all(|z| heads_of_history(universe, &join(x, z)) == heads_of_history(universe, &join(y, z)))
}
