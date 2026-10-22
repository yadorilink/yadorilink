//! Random histories that obey the author-side rule.
//!
//! A scenario simulates replicas, one per author. Each replica knows a
//! history; it either authors a change against that history or learns
//! another replica's history. Every authored change is checked with
//! [`verify_strict_safe`] against its author's pre-state before it is kept,
//! so every generated history is one honest strict authors can produce.
//!
//! Actions: writes at paths and directory prefixes (so concurrent writes
//! arise between replicas that have not synced), deletes, write-then-delete
//! by one author, recursive-delete-like changes that remove every present
//! entry under a directory in one change, multi-path writes, and conflict
//! preservation of consumed heads (own or foreign) at their conflict path.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    conflict_path, is_under, AuthorId, Change, ChangeId, Effect, History, Op, Path, Preservation,
    Universe, Version,
};
use crate::semantics::{heads_of_history, watermarks};
use crate::strict::verify_strict_safe;

/// A small deterministic pseudo-random generator (SplitMix64).
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`; `n` must be positive.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// True with probability `percent / 100`.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Shape of generated scenarios.
#[derive(Clone, Debug)]
pub struct GenConfig {
    pub authors: u32,
    /// Number of actions (authored changes and syncs).
    pub steps: usize,
    /// Paths writes choose from; `/` separates directories. Conflict paths
    /// are added as preservations create them.
    pub paths: Vec<Path>,
    /// Directories recursive deletes choose from.
    pub directories: Vec<Path>,
    /// Percentage of actions that are syncs.
    pub sync_percent: u64,
    /// Percentage of consumed heads that are preserved at their conflict
    /// path.
    pub preserve_percent: u64,
}

impl Default for GenConfig {
    fn default() -> Self {
        let paths = ["a", "a/b", "a/b/c", "a/d", "e", "e/f"];
        Self {
            authors: 3,
            steps: 24,
            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            directories: ["a", "a/b", "e"].iter().map(|p| (*p).to_owned()).collect(),
            sync_percent: 25,
            preserve_percent: 25,
        }
    }
}

/// A generated set of changes and the histories replicas ended with.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub seed: u64,
    pub universe: Universe,
    /// Every change in authoring order: a valid delivery order of the whole
    /// universe.
    pub order: Vec<ChangeId>,
    /// The history each replica knows at the end, indexed by author.
    pub replicas: Vec<History>,
    /// The history each change was authored against (its author's
    /// pre-state).
    pub pre_states: BTreeMap<ChangeId, History>,
}

impl Scenario {
    /// The history of every generated change.
    pub fn all(&self) -> History {
        self.order.iter().copied().collect()
    }

    /// `history` in authoring order, which is a valid delivery order: each
    /// change follows its author's earlier changes and its basis members.
    pub fn authoring_order(&self, history: &History) -> Vec<ChangeId> {
        self.order.iter().copied().filter(|id| history.contains(id)).collect()
    }
}

/// A random valid delivery order of `history`: each change follows its
/// author's earlier changes in `history` and its basis members.
pub fn random_delivery_order(
    universe: &Universe,
    history: &History,
    rng: &mut Rng,
) -> Vec<ChangeId> {
    let mut emitted: BTreeSet<ChangeId> = BTreeSet::new();
    let mut last_seq: BTreeMap<AuthorId, u64> = BTreeMap::new();
    let mut order = Vec::with_capacity(history.len());
    while order.len() < history.len() {
        let ready: Vec<ChangeId> = history
            .iter()
            .copied()
            .filter(|id| !emitted.contains(id))
            .filter(|&id| {
                let c = universe.change(id);
                last_seq.get(&c.author).copied().unwrap_or(0) + 1 == c.seq
                    && c.ops.iter().all(|op| {
                        op.basis.iter().all(|b| emitted.contains(b) || !history.contains(b))
                    })
            })
            .collect();
        assert!(!ready.is_empty(), "history has no valid delivery order");
        let next = *rng.pick(&ready);
        let c = universe.change(next);
        last_seq.insert(c.author, c.seq);
        emitted.insert(next);
        order.push(next);
    }
    order
}

struct Builder<'c> {
    config: &'c GenConfig,
    rng: Rng,
    universe: Universe,
    order: Vec<ChangeId>,
    replicas: Vec<History>,
    pre_states: BTreeMap<ChangeId, History>,
    next_id: u64,
    next_version: u64,
}

/// Generates a scenario. Deterministic in `seed` and `config`.
///
/// # Panics
///
/// When an authored change violates the author-side rule, which is a bug
/// in the generator.
pub fn generate(seed: u64, config: &GenConfig) -> Scenario {
    let mut b = Builder {
        config,
        rng: Rng::new(seed),
        universe: Universe::new(),
        order: Vec::new(),
        replicas: vec![History::new(); config.authors.max(1) as usize],
        pre_states: BTreeMap::new(),
        next_id: 1,
        next_version: 1,
    };
    for _ in 0..config.steps {
        b.action();
    }
    Scenario {
        seed,
        universe: b.universe,
        order: b.order,
        replicas: b.replicas,
        pre_states: b.pre_states,
    }
}

/// One operation an author intends, before preservation targets are added.
struct Intent {
    path: Path,
    put: bool,
    basis: Vec<ChangeId>,
}

impl Builder<'_> {
    fn action(&mut self) {
        let n = self.replicas.len();
        let author = self.rng.below(n);
        if n > 1 && self.rng.chance(self.config.sync_percent) {
            let from = self.rng.below(n);
            let learned = self.replicas[from].clone();
            self.replicas[author].extend(learned);
            return;
        }
        match self.rng.below(10) {
            0..=3 => {
                let path = self.rng.pick(&self.config.paths).clone();
                self.author_paths(author, &[path], true);
            }
            4 => {
                let first = self.rng.pick(&self.config.paths).clone();
                let second = self.rng.pick(&self.config.paths).clone();
                self.author_paths(author, &[first, second], true);
            }
            5 | 6 => self.delete_present(author),
            7 => {
                let path = self.rng.pick(&self.config.paths).clone();
                self.author_paths(author, std::slice::from_ref(&path), true);
                self.author_paths(author, &[path], false);
            }
            _ => self.recursive_delete(author),
        }
    }

    fn pre_heads(&self, author: usize) -> BTreeMap<Path, BTreeSet<ChangeId>> {
        heads_of_history(&self.universe, &self.replicas[author])
    }

    /// Deletes one path that currently has heads.
    fn delete_present(&mut self, author: usize) {
        let present: Vec<Path> = self.pre_heads(author).into_keys().collect();
        if present.is_empty() {
            return;
        }
        let path = self.rng.pick(&present).clone();
        self.author_paths(author, &[path], false);
    }

    /// Deletes every present entry at or below a directory, observing all
    /// of their heads, in one change.
    fn recursive_delete(&mut self, author: usize) {
        let dir = self.rng.pick(&self.config.directories).clone();
        let intents: Vec<Intent> = self
            .pre_heads(author)
            .into_iter()
            .filter(|(path, _)| is_under(path, &dir))
            .map(|(path, heads)| Intent { path, put: false, basis: heads.into_iter().collect() })
            .collect();
        if !intents.is_empty() {
            self.commit(author, intents);
        }
    }

    /// Writes (or deletes) each distinct path of `paths` with a random
    /// basis: a random subset of the current heads. An own head may be left
    /// out; it then stays alongside the new version.
    fn author_paths(&mut self, author: usize, paths: &[Path], put: bool) {
        let heads = self.pre_heads(author);
        let mut seen = BTreeSet::new();
        let mut intents = Vec::new();
        for path in paths {
            if !seen.insert(path.clone()) {
                continue;
            }
            let current = heads.get(path).cloned().unwrap_or_default();
            let basis: Vec<ChangeId> =
                current.into_iter().filter(|_| self.rng.chance(70)).collect();
            // A delete that consumes nothing is legal but says nothing.
            if !put && basis.is_empty() {
                continue;
            }
            intents.push(Intent { path: path.clone(), put, basis });
        }
        if !intents.is_empty() {
            self.commit(author, intents);
        }
    }

    /// Adds preservations, builds the change, checks it against its
    /// author's pre-state and records it.
    fn commit(&mut self, author: usize, intents: Vec<Intent>) {
        let me = AuthorId(author as u32);
        let pre = self.replicas[author].clone();
        let mut ops: Vec<Op> = Vec::new();
        for intent in &intents {
            let effect =
                if intent.put { Effect::Put(self.fresh_version()) } else { Effect::Delete };
            ops.push(Op { path: intent.path.clone(), effect, basis: intent.basis.clone() });
        }
        let mut preservations = Vec::new();
        for intent in &intents {
            for &source in &intent.basis {
                if !self.rng.chance(self.config.preserve_percent) {
                    continue;
                }
                let target = conflict_path(&intent.path, source);
                if ops.iter().any(|op| op.path == target) {
                    continue;
                }
                let Some(version) = self.universe.change(source).version_at(&intent.path) else {
                    continue;
                };
                ops.push(Op { path: target.clone(), effect: Effect::Put(version), basis: vec![] });
                preservations.push(Preservation {
                    source_path: intent.path.clone(),
                    source,
                    target_path: target,
                    version,
                });
            }
        }
        ops.sort_by(|a, b| a.path.cmp(&b.path));
        let seq = watermarks(&self.universe, &pre).get(&me).copied().unwrap_or(0) + 1;
        let change = Change { id: ChangeId(self.next_id), author: me, seq, ops, preservations };
        if let Err(violation) = verify_strict_safe(&self.universe, &pre, &change) {
            panic!("generated change violates the author-side rule: {violation:?}: {change:?}");
        }
        self.next_id += 1;
        self.pre_states.insert(change.id, pre);
        self.order.push(change.id);
        self.replicas[author].insert(change.id);
        self.universe.insert(change);
    }

    fn fresh_version(&mut self) -> Version {
        let v = Version(self.next_version);
        self.next_version += 1;
        v
    }
}
