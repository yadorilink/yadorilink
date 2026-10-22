//! The harness accepts a correct incremental implementation and reports
//! broken ones.
//!
//! The reference implementation below is the incremental transition and
//! join rule over a state of watermarks and head lists; the oracle knows
//! nothing about it.

use std::collections::BTreeMap;

use yadorilink_dcf_oracle::{check, check_join, AuthorId, ChangeId, CheckConfig, Heads, Universe};

#[derive(Clone, Default)]
struct State {
    watermarks: BTreeMap<AuthorId, u64>,
    heads: BTreeMap<String, Vec<ChangeId>>,
}

impl State {
    fn seen(&self, u: &Universe, x: ChangeId) -> bool {
        let c = u.change(x);
        c.seq <= self.watermarks.get(&c.author).copied().unwrap_or(0)
    }

    fn heads(&self) -> Heads {
        self.heads.iter().map(|(p, h)| (p.clone(), h.iter().copied().collect())).collect()
    }
}

fn step(u: &Universe, state: &mut State, id: ChangeId, consume: bool) {
    let c = u.change(id);
    state.watermarks.insert(c.author, c.seq);
    for op in &c.ops {
        let heads = state.heads.entry(op.path.clone()).or_default();
        if consume {
            heads.retain(|x| !c.in_basis(&op.path, *x));
        }
        if c.lands(&op.path) {
            heads.push(id);
        }
    }
}

fn fold(u: &Universe, order: &[ChangeId], consume: bool) -> State {
    let mut state = State::default();
    for &id in order {
        step(u, &mut state, id, consume);
    }
    state
}

fn join(u: &Universe, a: &State, b: &State) -> State {
    let mut out = State { watermarks: a.watermarks.clone(), heads: BTreeMap::new() };
    for (&author, &w) in &b.watermarks {
        let entry = out.watermarks.entry(author).or_insert(0);
        *entry = (*entry).max(w);
    }
    let empty = Vec::new();
    let paths: std::collections::BTreeSet<&String> = a.heads.keys().chain(b.heads.keys()).collect();
    for path in paths {
        let ha = a.heads.get(path).unwrap_or(&empty);
        let hb = b.heads.get(path).unwrap_or(&empty);
        let mut heads: Vec<ChangeId> =
            ha.iter().copied().filter(|x| hb.contains(x) || !b.seen(u, *x)).collect();
        heads.extend(hb.iter().copied().filter(|x| !a.seen(u, *x)));
        out.heads.insert(path.clone(), heads);
    }
    out
}

fn config() -> CheckConfig {
    CheckConfig { seeds: 0..150, ..CheckConfig::default() }
}

#[test]
fn reference_step_matches_the_oracle() {
    let report =
        check(&config(), |u, order| fold(u, order, true).heads()).unwrap_or_else(|m| panic!("{m}"));
    assert_eq!(report.scenarios, 150);
    assert!(report.comparisons > 150);
}

#[test]
fn reference_join_matches_the_oracle() {
    check_join(&config(), |u, l, r| join(u, &fold(u, l, true), &fold(u, r, true)).heads())
        .unwrap_or_else(|m| panic!("{m}"));
}

#[test]
fn step_that_ignores_bases_is_caught() {
    let mismatch = check(&config(), |u, order| fold(u, order, false).heads()).unwrap_err();
    assert_ne!(mismatch.expected, mismatch.actual);
    assert!(mismatch.to_string().contains("expected"));
}

#[test]
fn join_that_unions_heads_is_caught() {
    let result = check_join(&config(), |u, l, r| {
        let (a, b) = (fold(u, l, true), fold(u, r, true));
        let mut heads = a.heads();
        for (p, h) in b.heads() {
            heads.entry(p).or_default().extend(h);
        }
        heads
    });
    assert!(result.is_err(), "a join that resurrects consumed heads must be reported");
}

#[test]
fn join_without_watermarks_is_caught() {
    // Keeping a head only when both sides hold it drops concurrent writes.
    let result = check_join(&config(), |u, l, r| {
        let (a, b) = (fold(u, l, true), fold(u, r, true));
        let bh = b.heads();
        a.heads()
            .into_iter()
            .map(|(p, h)| {
                let other = bh.get(&p).cloned().unwrap_or_default();
                (p, h.intersection(&other).copied().collect())
            })
            .collect()
    });
    assert!(result.is_err());
}
