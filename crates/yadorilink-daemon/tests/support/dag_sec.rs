//! Reusable model for the change-history Strong Eventual Consistency
//! property suite.
//!
//! This is an independent, in-memory reimplementation of the change-DAG
//! semantics — the batch materialization fold and a genuinely incremental
//! applier — plus a seeded workload/topology generator. It is deliberately
//! a *second* implementation of the same rules: the property suite compares
//! it against itself (incremental vs. batch, permuted vs. sequential
//! delivery) and against the production per-path resolver
//! (`yadorilink_peer_session::peer_session::resolve_path_heads`), so a bug in
//! either the model or the resolver surfaces as a disagreement rather than
//! two implementations sharing a blind spot.
//!
//! Materialized state is a pure function of the *set* of applied changes:
//! `apply` at the set level is trivially commutative, associative, and
//! idempotent, and the incremental applier here streams changes one at a
//! time (buffering any that arrive before their ancestry) and must always
//! reach the same state as the batch fold of the final set.

use std::collections::{BTreeMap, BTreeSet};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};

use yadorilink_replica_engine::conflict::{
    resolve_path_heads, PathHead, PathHeadContent, PathResolution,
};

/// A content identity — two changes carrying the same `Version` for a path
/// mean the byte-identical file; different versions mean different bytes.
pub type Version = u64;

/// The materialized folder state: path -> the content version living there
/// (a conflict copy is just another path in this map). A path absent from
/// the map is absent on disk.
pub type Materialized = BTreeMap<String, Version>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Create or update `path` with `version`.
    Put { path: String, version: Version },
    /// Tombstone `path`.
    Del { path: String },
    /// Rename `from` to `to`, landing `version` at `to`.
    Mov { from: String, to: String, version: Version },
}

#[derive(Clone, Debug)]
pub struct Change {
    pub device: u8,
    pub lamport: u64,
    /// Indices of parent changes in the owning `Dag`.
    pub parents: Vec<usize>,
    pub ops: Vec<Op>,
    /// Canonical content hash — the change's identity and the tie-break
    /// used when two changes are concurrent.
    pub hash: [u8; 32],
}

/// The global append-only change store. Ancestor sets are precomputed on
/// append so ancestry checks are O(1) lookups during folds.
#[derive(Default)]
pub struct Dag {
    pub changes: Vec<Change>,
    ancestors: Vec<BTreeSet<usize>>,
}

impl Dag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a change authored by `device` whose parents are `parents`
    /// (indices of already-appended changes) with operations `ops`.
    /// `lamport` is `max(parent lamports) + 1`. Returns the new index.
    pub fn append(&mut self, device: u8, mut parents: Vec<usize>, ops: Vec<Op>) -> usize {
        parents.sort_unstable();
        parents.dedup();
        let lamport = parents.iter().map(|&p| self.changes[p].lamport).max().unwrap_or(0) + 1;
        let hash = hash_change(device, lamport, &parents, &ops, &self.changes);
        let mut anc = BTreeSet::new();
        for &p in &parents {
            anc.insert(p);
            for &a in &self.ancestors[p] {
                anc.insert(a);
            }
        }
        let idx = self.changes.len();
        self.changes.push(Change { device, lamport, parents, ops, hash });
        self.ancestors.push(anc);
        idx
    }

    /// Whether `a` is a strict ancestor of `b`.
    pub fn is_ancestor(&self, a: usize, b: usize) -> bool {
        self.ancestors[b].contains(&a)
    }

    /// The heads of a held subset: changes in `held` with no descendant
    /// also in `held`. These are exactly the parents a device's next local
    /// change lists.
    pub fn heads_of(&self, held: &BTreeSet<usize>) -> Vec<usize> {
        held.iter()
            .copied()
            .filter(|&c| !held.iter().any(|&d| d != c && self.is_ancestor(c, d)))
            .collect()
    }
}

fn hash_change(
    device: u8,
    lamport: u64,
    parents: &[usize],
    ops: &[Op],
    existing: &[Change],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([device]);
    h.update(lamport.to_le_bytes());
    for &p in parents {
        h.update(existing[p].hash);
    }
    for op in ops {
        match op {
            Op::Put { path, version } => {
                h.update([1u8]);
                h.update((path.len() as u32).to_le_bytes());
                h.update(path.as_bytes());
                h.update(version.to_le_bytes());
            }
            Op::Del { path } => {
                h.update([2u8]);
                h.update((path.len() as u32).to_le_bytes());
                h.update(path.as_bytes());
            }
            Op::Mov { from, to, version } => {
                h.update([3u8]);
                h.update((from.len() as u32).to_le_bytes());
                h.update(from.as_bytes());
                h.update((to.len() as u32).to_le_bytes());
                h.update(to.as_bytes());
                h.update(version.to_le_bytes());
            }
        }
    }
    h.finalize().into()
}

/// The content hash for a version — a stand-in for the real file version
/// hash, used as the conflict-copy disambiguator.
pub fn version_hash(v: Version) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"version");
    h.update(v.to_le_bytes());
    h.finalize().into()
}

/// Builds the head this change contributes to `path`, or `None` if the
/// change does not touch `path`. A `Move` is a hint desugared to
/// `Delete{from}` + `Create{to}`: it contributes a removing head at its source
/// and a content head at its destination, so concurrency resolves per
/// desugared path (there is no special Move-vs-Move rule — two moves to the
/// same target are an ordinary content conflict there; to different targets,
/// both land).
fn head_for(dag: &Dag, c: usize, path: &str) -> Option<PathHead> {
    let ch = &dag.changes[c];
    let mut touches = false;
    let mut content: Option<Version> = None;
    for op in &ch.ops {
        match op {
            Op::Put { path: p, version } if p == path => {
                touches = true;
                content = Some(*version);
            }
            Op::Del { path: p } if p == path => {
                touches = true;
                content = None;
            }
            Op::Mov { to, version, .. } if to == path => {
                touches = true;
                content = Some(*version);
            }
            Op::Mov { from, .. } if from == path => {
                touches = true;
                // removing head unless a content head for the same path was
                // also set (a self-move, which the generator never emits).
            }
            _ => {}
        }
    }
    if !touches {
        return None;
    }
    Some(PathHead {
        change_hash: ch.hash,
        rank: ch.lamport,
        device_id: format!("device-{}", ch.device),
        // The generator never emits a retroactive re-assertion, so the
        // signing device is always the device that wrote the content --
        // the only case where these two identities diverge.
        naming_device_id: format!("device-{}", ch.device),
        content: content
            .map(|v| PathHeadContent { version_hash: version_hash(v), mtime_unix_nanos: v as i64 }),
    })
}

fn version_at_head(dag: &Dag, c: usize, path: &str) -> Option<Version> {
    let ch = &dag.changes[c];
    let mut v = None;
    for op in &ch.ops {
        match op {
            Op::Put { path: p, version } if p == path => v = Some(*version),
            Op::Mov { to, version, .. } if to == path => v = Some(*version),
            _ => {}
        }
    }
    v
}

/// Builds the resolver inputs for one path from its *combined* heads: the
/// changes that directly touch the path (`direct`, already reduced to live
/// heads among themselves) plus a derived content head — the content a
/// losing change of some other path materializes *at this* conflict-copy
/// path. Cross-supersession is applied across the whole combined set, so a
/// change that directly touches this path and descends from the derived
/// losing head supersedes it (a delete of a conflict copy sticks). Returns
/// the `PathHead`s and, aligned with them, each head's `(change, content
/// version)` for recovering the winning/losing versions after resolution.
fn build_candidates(
    dag: &Dag,
    path: &str,
    direct: &[usize],
    derived: Option<(usize, Version)>,
) -> (Vec<PathHead>, Vec<(usize, Version)>) {
    let mut cand: Vec<(usize, Option<Version>)> = direct.iter().map(|&c| (c, None)).collect();
    if let Some((c, v)) = derived {
        cand.push((c, Some(v)));
    }
    let cand_changes: Vec<usize> = cand.iter().map(|(c, _)| *c).collect();
    let mut inputs = Vec::new();
    let mut meta = Vec::new();
    for (idx, &(c, dv)) in cand.iter().enumerate() {
        // Superseded iff another candidate change is a descendant of `c`.
        let superseded =
            cand_changes.iter().enumerate().any(|(j, &d)| j != idx && dag.is_ancestor(c, d));
        if superseded {
            continue;
        }
        match dv {
            Some(v) => {
                inputs.push(PathHead {
                    change_hash: dag.changes[c].hash,
                    rank: dag.changes[c].lamport,
                    device_id: format!("device-{}", dag.changes[c].device),
                    naming_device_id: format!("device-{}", dag.changes[c].device),
                    content: Some(PathHeadContent {
                        version_hash: version_hash(v),
                        mtime_unix_nanos: v as i64,
                    }),
                });
                meta.push((c, v));
            }
            None => {
                if let Some(h) = head_for(dag, c, path) {
                    let v = version_at_head(dag, c, path).unwrap_or(0);
                    inputs.push(h);
                    meta.push((c, v));
                }
            }
        }
    }
    (inputs, meta)
}

/// The materialization fold that treats conflict-copy paths as first-class.
///
/// A conflict copy is not a blind post-step: the losing change of a
/// concurrent contest materializes content *at* the conflict-copy path, and
/// that path is then folded like any other — combining that derived content
/// head with any changes that directly touch the copy path (e.g. a later
/// delete of the copy). Because supersession runs across the combined set, a
/// delete that descends from the losing head removes the copy for good; the
/// copy is only re-materialized if genuinely new concurrency arises. This is
/// computed to a fixpoint over the derived conflict-copy paths (bounded: copy
/// names embed the losing version hash, so the set of derived paths is
/// finite).
///
/// Returns the materialized state and the set of paths that resolved to
/// *absent while holding a tombstone* — the paths a correct fold must never
/// resurrect.
fn fold_materialize<F>(
    dag: &Dag,
    seed_paths: &BTreeSet<String>,
    direct_live: F,
) -> (Materialized, BTreeSet<String>)
where
    F: Fn(&str) -> Vec<usize>,
{
    // Each conflict-copy path is produced by exactly one losing change (copy
    // names embed that change's version hash), so a single derived head per
    // path suffices.
    let mut derived: BTreeMap<String, (usize, Version)> = BTreeMap::new();
    loop {
        let mut next = derived.clone();
        let paths: BTreeSet<String> =
            seed_paths.iter().cloned().chain(derived.keys().cloned()).collect();
        for path in &paths {
            let direct = direct_live(path);
            let (inputs, meta) = build_candidates(dag, path, &direct, derived.get(path).copied());
            if inputs.is_empty() {
                continue;
            }
            if let PathResolution::Present { conflict_copies, .. } =
                resolve_path_heads(path, &inputs)
            {
                for cc in conflict_copies {
                    next.insert(cc.path.clone(), meta[cc.head]);
                }
            }
        }
        // `derived` only ever grows, so a stable size means a fixpoint.
        if next.len() == derived.len() {
            break;
        }
        derived = next;
    }

    let mut out = Materialized::new();
    let mut tombstoned = BTreeSet::new();
    let paths: BTreeSet<String> =
        seed_paths.iter().cloned().chain(derived.keys().cloned()).collect();
    for path in &paths {
        let direct = direct_live(path);
        let (inputs, meta) = build_candidates(dag, path, &direct, derived.get(path).copied());
        if inputs.is_empty() {
            continue;
        }
        let had_tombstone = inputs.iter().any(|h| h.content.is_none());
        match resolve_path_heads(path, &inputs) {
            PathResolution::Absent => {
                if had_tombstone {
                    tombstoned.insert(path.clone());
                }
            }
            PathResolution::Present { winner, .. } => {
                out.insert(path.clone(), meta[winner].1);
            }
        }
    }
    (out, tombstoned)
}

/// The live heads for a single path in `applied`: changes that touch the
/// path and have no *descendant that also touches the path*. Supersession is
/// per-path on purpose — a change that only edits `g.txt` does not supersede
/// an earlier `f.txt` edit in its ancestry, because the delta model carries
/// an untouched path's content forward. Only a later change *to the same
/// path* supersedes an earlier one.
fn live_heads_for_path(dag: &Dag, applied: &BTreeSet<usize>, path: &str) -> Vec<usize> {
    let touching: Vec<usize> =
        applied.iter().copied().filter(|&c| head_for(dag, c, path).is_some()).collect();
    touching
        .iter()
        .copied()
        .filter(|&c| !touching.iter().any(|&d| d != c && dag.is_ancestor(c, d)))
        .collect()
}

fn touched_paths_of_set(dag: &Dag, applied: &BTreeSet<usize>) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for &c in applied {
        for op in &dag.changes[c].ops {
            match op {
                Op::Put { path, .. } | Op::Del { path } => {
                    paths.insert(path.clone());
                }
                Op::Mov { from, to, .. } => {
                    paths.insert(from.clone());
                    paths.insert(to.clone());
                }
            }
        }
    }
    paths
}

/// The batch materialization fold over an applied set. Direct live heads are
/// recomputed from scratch (`live_heads_for_path`), so this shares no
/// incremental bookkeeping with `Incremental` — the conflict-copy fixpoint
/// logic is shared, but the head derivation each feeds it is independent.
pub fn batch_fold(dag: &Dag, applied: &BTreeSet<usize>) -> Materialized {
    let seeds = touched_paths_of_set(dag, applied);
    fold_materialize(dag, &seeds, |path| live_heads_for_path(dag, applied, path)).0
}

/// A genuinely incremental applier: changes are delivered one at a time
/// (idempotently; a change whose parents are not all present is buffered
/// until its ancestry completes, never applied ahead of it), and the live
/// head set per path is maintained incrementally rather than recomputed.
/// `materialize` folds those incrementally-maintained heads, so agreement
/// with `batch_fold(applied)` is a real cross-check, not a tautology.
pub struct Incremental<'a> {
    dag: &'a Dag,
    applied: BTreeSet<usize>,
    buffer: Vec<usize>,
    heads_by_path: BTreeMap<String, Vec<usize>>,
}

impl<'a> Incremental<'a> {
    pub fn new(dag: &'a Dag) -> Self {
        Self { dag, applied: BTreeSet::new(), buffer: Vec::new(), heads_by_path: BTreeMap::new() }
    }

    fn parents_ready(&self, c: usize) -> bool {
        self.dag.changes[c].parents.iter().all(|p| self.applied.contains(p))
    }

    /// Delivers one change (a no-op if already applied — idempotence).
    pub fn deliver(&mut self, c: usize) {
        if self.applied.contains(&c) {
            return;
        }
        if !self.buffer.contains(&c) {
            self.buffer.push(c);
        }
        self.drain_buffer();
    }

    fn drain_buffer(&mut self) {
        loop {
            let ready: Vec<usize> = self
                .buffer
                .iter()
                .copied()
                .filter(|&c| !self.applied.contains(&c) && self.parents_ready(c))
                .collect();
            if ready.is_empty() {
                break;
            }
            for c in ready {
                self.apply(c);
            }
            self.buffer.retain(|c| !self.applied.contains(c));
        }
    }

    fn apply(&mut self, c: usize) {
        self.applied.insert(c);
        let touched = touched_paths(&self.dag.changes[c]);
        for path in touched {
            let entry = self.heads_by_path.entry(path.clone()).or_default();
            // Drop any current head this change supersedes (it descends
            // from it), then add this change as a head unless an existing
            // head already supersedes it.
            entry.retain(|&h| !self.dag.is_ancestor(h, c));
            let superseded = entry.iter().any(|&h| self.dag.is_ancestor(c, h));
            if !superseded && !entry.contains(&c) {
                entry.push(c);
            }
        }
    }

    /// Folds the incrementally-maintained head sets into materialized state.
    /// Feeds its own `heads_by_path` (maintained incrementally, independent of
    /// the batch recompute) into the shared conflict-copy fixpoint fold.
    pub fn materialize(&self) -> Materialized {
        let seeds: BTreeSet<String> = self.heads_by_path.keys().cloned().collect();
        fold_materialize(self.dag, &seeds, |path| {
            self.heads_by_path.get(path).cloned().unwrap_or_default()
        })
        .0
    }
}

fn touched_paths(ch: &Change) -> Vec<String> {
    let mut paths = Vec::new();
    for op in &ch.ops {
        match op {
            Op::Put { path, .. } | Op::Del { path } => paths.push(path.clone()),
            Op::Mov { from, to, .. } => {
                paths.push(from.clone());
                paths.push(to.clone());
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

// ---------------------------------------------------------------------------
// Seeded workload + topology generator.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    /// Two halves that sync internally, bridged only intermittently.
    Split,
    /// A linear chain `0-1-2-3`: no direct link between non-adjacent
    /// devices, so changes propagate only by store-and-forward.
    Chain,
    /// A hub (device 0) with spokes.
    Star,
    /// Links appear and disappear at random each round.
    Dynamic,
}

const TOPOLOGIES: [Topology; 4] =
    [Topology::Split, Topology::Chain, Topology::Star, Topology::Dynamic];

const PATH_POOL: [&str; 4] = ["a.txt", "b.txt", "notes/c.txt", "notes/d.txt"];

/// The result of one seeded simulation, after a final full-gossip
/// quiescence phase that reconnects every device.
pub struct Simulation {
    pub topology: Topology,
    pub device_count: usize,
    pub dag: Dag,
    /// Every change appended over the whole run.
    pub all_changes: BTreeSet<usize>,
    /// Final held set per device.
    pub held: Vec<BTreeSet<usize>>,
    /// Final incrementally-materialized state per device.
    pub state: Vec<Materialized>,
}

/// Runs one fully-deterministic simulation for `seed`: random local edits
/// across N devices, gossip under a randomly chosen topology (with
/// partitions, dynamic bridges, duplicated and reordered delivery, and
/// occasional crash-restart replays), then a final full-gossip phase so
/// every device reaches quiescence.
pub fn simulate(seed: u64) -> Simulation {
    let mut rng = StdRng::seed_from_u64(seed);
    let device_count = rng.random_range(2..=4);
    let topology = TOPOLOGIES[rng.random_range(0..TOPOLOGIES.len())];
    let rounds = rng.random_range(6..14);

    let mut dag = Dag::new();
    let mut held: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); device_count];
    let mut engines_delivery: Vec<Vec<usize>> = vec![Vec::new(); device_count];
    let mut next_version: Version = 1;

    let deliver = |held: &mut BTreeSet<usize>, log: &mut Vec<usize>, c: usize| {
        if held.insert(c) {
            log.push(c);
        }
    };

    for round in 0..rounds {
        // 1) Local edits.
        for dev in 0..device_count {
            if rng.random_range(0..100) < 60 {
                let parents = dag.heads_of(&held[dev]);
                let op = random_op(&mut rng, &held[dev], &dag, &mut next_version);
                let idx = dag.append(dev as u8, parents, vec![op]);
                deliver(&mut held[dev], &mut engines_delivery[dev], idx);
            }
        }
        // 2) Gossip along currently-open links (full held-set exchange —
        //    store-and-forward: a device shares everything it holds).
        for (u, v) in open_links(topology, device_count, round, &mut rng) {
            let u_set: Vec<usize> = held[u].iter().copied().collect();
            let v_set: Vec<usize> = held[v].iter().copied().collect();
            for c in v_set {
                deliver(&mut held[u], &mut engines_delivery[u], c);
            }
            for c in u_set {
                deliver(&mut held[v], &mut engines_delivery[v], c);
            }
        }
    }

    // 3) Final full-gossip quiescence: connect everyone for enough rounds to
    //    cover the chain's diameter, so every device ends with the same
    //    held set.
    for _ in 0..device_count {
        for u in 0..device_count {
            for v in (u + 1)..device_count {
                let u_set: Vec<usize> = held[u].iter().copied().collect();
                let v_set: Vec<usize> = held[v].iter().copied().collect();
                for c in v_set {
                    deliver(&mut held[u], &mut engines_delivery[u], c);
                }
                for c in u_set {
                    deliver(&mut held[v], &mut engines_delivery[v], c);
                }
            }
        }
    }

    // 4) Feed each device's received-change log into an incremental engine,
    //    reordered and duplicated, with an occasional crash-restart replay,
    //    then materialize.
    let mut state = Vec::with_capacity(device_count);
    for dev in 0..device_count {
        let mut order = engines_delivery[dev].clone();
        permute_with_dups(&mut rng, &mut order);
        let mut engine = Incremental::new(&dag);
        for &c in &order {
            engine.deliver(c);
        }
        if rng.random_range(0..100) < 30 {
            // Crash-restart: throw away the in-memory engine and replay the
            // whole held set in a fresh random order — must reach the same
            // state (replay idempotence / persistence recovery).
            let mut replay: Vec<usize> = held[dev].iter().copied().collect();
            permute_with_dups(&mut rng, &mut replay);
            let mut fresh = Incremental::new(&dag);
            for &c in &replay {
                fresh.deliver(c);
            }
            engine = fresh;
        }
        state.push(engine.materialize());
    }

    let all_changes: BTreeSet<usize> = (0..dag.changes.len()).collect();
    Simulation { topology, device_count, dag, all_changes, held, state }
}

fn random_op(
    rng: &mut StdRng,
    held: &BTreeSet<usize>,
    dag: &Dag,
    next_version: &mut Version,
) -> Op {
    // Prefer editing/deleting/moving a path this device currently has, so
    // tombstones and moves land on real content rather than always creating.
    let current = batch_fold(dag, held);
    let existing: Vec<String> = current.keys().cloned().collect();
    match rng.random_range(0..10) {
        0..=5 => {
            let path = PATH_POOL[rng.random_range(0..PATH_POOL.len())].to_string();
            let version = *next_version;
            *next_version += 1;
            Op::Put { path, version }
        }
        6..=7 if !existing.is_empty() => {
            let path = existing[rng.random_range(0..existing.len())].clone();
            Op::Del { path }
        }
        8..=9 if !existing.is_empty() => {
            let from = existing[rng.random_range(0..existing.len())].clone();
            let mut to = PATH_POOL[rng.random_range(0..PATH_POOL.len())].to_string();
            if to == from {
                to = format!("{from}.moved");
            }
            let version = *next_version;
            *next_version += 1;
            Op::Mov { from, to, version }
        }
        _ => {
            let path = PATH_POOL[rng.random_range(0..PATH_POOL.len())].to_string();
            let version = *next_version;
            *next_version += 1;
            Op::Put { path, version }
        }
    }
}

fn open_links(topology: Topology, n: usize, round: usize, rng: &mut StdRng) -> Vec<(usize, usize)> {
    let mut links = Vec::new();
    match topology {
        Topology::Chain => {
            for i in 0..n.saturating_sub(1) {
                links.push((i, i + 1));
            }
        }
        Topology::Star => {
            for i in 1..n {
                links.push((0, i));
            }
        }
        Topology::Split => {
            let mid = n / 2;
            for i in 0..mid.saturating_sub(1) {
                links.push((i, i + 1));
            }
            for i in mid..n.saturating_sub(1) {
                links.push((i, i + 1));
            }
            // Intermittent bridge between the halves.
            if mid > 0 && mid < n && round.is_multiple_of(3) {
                links.push((mid - 1, mid));
            }
        }
        Topology::Dynamic => {
            for u in 0..n {
                for v in (u + 1)..n {
                    if rng.random_range(0..100) < 40 {
                        links.push((u, v));
                    }
                }
            }
        }
    }
    links
}

/// Randomly permutes `order` and injects a few duplicate deliveries — the
/// input to the idempotence/commutativity checks.
pub fn permute_with_dups(rng: &mut StdRng, order: &mut Vec<usize>) {
    // Fisher-Yates.
    let len = order.len();
    for i in (1..len).rev() {
        let j = rng.random_range(0..=i);
        order.swap(i, j);
    }
    // Duplicate a handful of entries at random positions.
    if !order.is_empty() {
        let dups = rng.random_range(0..=order.len().min(4));
        for _ in 0..dups {
            let pick = order[rng.random_range(0..order.len())];
            let at = rng.random_range(0..=order.len());
            order.insert(at, pick);
        }
    }
}

/// The set of paths that resolve to *absent while holding a tombstone* — the
/// paths a correct fold must never resurrect. Derived from the same
/// conflict-copy-aware fixpoint fold as `batch_fold`, so a conflict-copy path
/// that has been deleted counts as tombstoned (its derived content head is
/// superseded by the delete) rather than being spuriously excluded.
pub fn tombstoned_paths(dag: &Dag, applied: &BTreeSet<usize>) -> BTreeSet<String> {
    let seeds = touched_paths_of_set(dag, applied);
    fold_materialize(dag, &seeds, |path| live_heads_for_path(dag, applied, path)).1
}
