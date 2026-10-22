//! Strong Eventual Consistency property suite for the change-history DAG.
//!
//! For a battery of seeds, a workload of random operations is generated
//! across several simulated devices and gossiped under a randomly chosen
//! partition topology (split halves with an intermittent bridge, a linear
//! chain that only converges by store-and-forward, a star, and randomly
//! appearing/disappearing links), with duplicated and reordered delivery
//! and occasional crash-restart replays. After every device reaches
//! quiescence, each run asserts the guarantees a convergent replicated
//! store must hold:
//!
//! 1. **Convergence to the reference fold** — every device's materialized
//!    state equals an independent batch fold of the change set it holds,
//!    and every device that ends up holding the same set holds the same
//!    state.
//! 2. **Commutativity + idempotence** — the same change set delivered in
//!    different orders, with duplicates, yields identical state, and the
//!    incrementally-maintained state always equals the from-scratch batch
//!    fold.
//! 3. **No resurrection** — a path with a live tombstone and no concurrent
//!    content is never present in the materialized state.
//! 4. **Identical conflict-copy naming** — two devices holding the same set
//!    produce byte-identical conflict-copy paths without communicating.
//! 5. **Store-and-forward** — a device that never connects to the origin
//!    still converges to the origin's state through an intermediary.
//!
//! The reference model and the incremental applier live in
//! `dst_support::dag_sec`; both fold concurrency through the production
//! resolver `yadorilink_peer_session::peer_session::resolve_path_heads`, so a
//! bug in that resolver surfaces here as a convergence failure with a
//! reproducing seed. A failing seed is appended to the regression corpus
//! and replayed by `corpus_regressions_replay`.
//!
//! This suite does not drive the real `PeerSyncSession::run` loop or change
//! store over a simulated `PeerChannel` (the pattern in
//! `dst_peer_reconcile_race.rs`); it pins the semantics the wire layer must
//! preserve.

// Not a simulation scenario: no `async fn`, no `.await`, and no simulator
// API anywhere in this file or in the model it drives, so it is ungated and
// runs under every plain `cargo test`. It takes about a second.
//
// The model lives in `tests/support/` rather than `tests/dst_support/` for
// the same reason this file has no gate: `dst_support` is gated on the
// simulation cfgs because everything in it builds a simulated runtime, and
// `dag_sec` does not.
mod support;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::PathBuf;

use rand::rngs::StdRng;
use rand::SeedableRng;

use support::dag_sec::{
    batch_fold, permute_with_dups, simulate, tombstoned_paths, Dag, Incremental, Materialized, Op,
    Simulation,
};

/// How many seeds each sweep covers. Kept modest so the suite stays fast;
/// the corpus replay below re-checks any historically
/// failing seed regardless of this window.
const SWEEP_SEEDS: u64 = 160;

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/dag_sec_failures.jsonl")
}

/// Records a failing seed to the regression corpus so it replays in CI even
/// after the sweep window moves on.
fn record_failure(seed: u64, kind: &str, detail: &str) {
    let path = corpus_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let line = format!(
        "{{\"seed\":{seed},\"kind\":\"{}\",\"detail\":\"{}\"}}\n",
        kind.replace('"', "'"),
        detail.replace('"', "'").replace('\n', " ")
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// The seeds previously recorded as failing, so they are always re-checked.
fn recorded_failing_seeds() -> Vec<u64> {
    let Ok(text) = std::fs::read_to_string(corpus_path()) else { return Vec::new() };
    let mut seeds = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.split("\"seed\":").nth(1) {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(s) = digits.parse::<u64>() {
                seeds.push(s);
            }
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

/// Runs every SEC assertion for one simulated seed, returning a
/// human-readable failure (with the seed) on the first violation.
fn check_seed(seed: u64) -> Result<(), String> {
    let sim = simulate(seed);
    let reference = batch_fold(&sim.dag, &sim.all_changes);

    // (1) Convergence: after quiescence every device holds the full set and
    // its incrementally-maintained state equals the independent reference
    // fold of that set.
    for dev in 0..sim.device_count {
        if sim.held[dev] != sim.all_changes {
            return Err(format!(
                "seed {seed} ({:?}): device {dev} did not reach quiescence — held {} of {} changes",
                sim.topology,
                sim.held[dev].len(),
                sim.all_changes.len()
            ));
        }
        if sim.state[dev] != reference {
            return Err(format!(
                "seed {seed} ({:?}): device {dev} diverged from the reference fold\n{}",
                sim.topology,
                first_difference(&sim.state[dev], &reference)
            ));
        }
    }

    // (4) Identical conflict-copy naming: every device's materialized map
    // (which includes conflict-copy paths) is identical.
    for dev in 1..sim.device_count {
        if sim.state[dev] != sim.state[0] {
            return Err(format!(
                "seed {seed} ({:?}): devices 0 and {dev} disagree on materialized state / conflict names\n{}",
                sim.topology,
                first_difference(&sim.state[0], &sim.state[dev])
            ));
        }
    }

    // (2) Commutativity + idempotence: deliver the full set in two more
    // independently permuted-and-duplicated orders; both must reproduce the
    // reference fold, proving the result is a pure function of the set.
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5EC_5EC);
    for attempt in 0..2 {
        let mut order: Vec<usize> = sim.all_changes.iter().copied().collect();
        permute_with_dups(&mut rng, &mut order);
        let mut engine = Incremental::new(&sim.dag);
        for &c in &order {
            engine.deliver(c);
        }
        let permuted = engine.materialize();
        if permuted != reference {
            return Err(format!(
                "seed {seed} ({:?}): permuted delivery attempt {attempt} produced a different state\n{}",
                sim.topology,
                first_difference(&permuted, &reference)
            ));
        }
    }

    // (3) No resurrection: nothing tombstoned-with-no-concurrent-content may
    // appear in the materialized state.
    let ghosts = tombstoned_paths(&sim.dag, &sim.all_changes);
    for path in &ghosts {
        if reference.contains_key(path) {
            return Err(format!(
                "seed {seed} ({:?}): tombstoned path {path:?} was resurrected into the state",
                sim.topology
            ));
        }
    }

    Ok(())
}

fn first_difference(a: &Materialized, b: &Materialized) -> String {
    let mut keys: BTreeSet<&String> = BTreeSet::new();
    keys.extend(a.keys());
    keys.extend(b.keys());
    for k in keys {
        if a.get(k) != b.get(k) {
            return format!("  path {k:?}: {:?} vs {:?}", a.get(k), b.get(k));
        }
    }
    "  (no path-level difference found)".to_string()
}

#[test]
fn sec_convergence_seeded_sweep() {
    let mut failures = Vec::new();
    for seed in 0..SWEEP_SEEDS {
        if let Err(e) = check_seed(seed) {
            record_failure(seed, "convergence", &e);
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{} SEC violation(s):\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn corpus_regressions_replay() {
    let mut failures = Vec::new();
    for seed in recorded_failing_seeds() {
        if let Err(e) = check_seed(seed) {
            failures.push(e);
        }
    }
    assert!(
        failures.is_empty(),
        "recorded regression seed(s) still failing:\n{}",
        failures.join("\n")
    );
}

/// A device that never connects to the origin still converges to the
/// origin's state through an intermediary (store-and-forward), and the
/// concurrent-edit conflict copy is named identically on both even though
/// they never communicated.
#[test]
fn store_and_forward_chain_converges() {
    let mut dag = Dag::new();
    // Device A's history for f.txt, plus an unrelated file.
    let a1 = dag.append(0, vec![], vec![Op::Put { path: "f.txt".into(), version: 1 }]);
    let a2 = dag.append(0, vec![a1], vec![Op::Put { path: "f.txt".into(), version: 2 }]);
    let a3 = dag.append(0, vec![a2], vec![Op::Put { path: "g.txt".into(), version: 3 }]);

    // Device B, having synced A's history, makes a concurrent edit to f.txt
    // (parents are A's heads it has seen, but NOT descending from a later A
    // edit — here A made no later edit, so B's edit is concurrent with a2's
    // successor line via a fresh sibling: parent a1, not a2).
    let b1 = dag.append(1, vec![a1], vec![Op::Put { path: "f.txt".into(), version: 99 }]);

    // Store-and-forward: A never connects to C. A syncs to B; B later syncs
    // to C. C's held set is whatever B forwards — all of A's changes plus
    // B's own — with no A<->C session ever.
    let b_held: BTreeSet<usize> = [a1, a2, a3, b1].into_iter().collect();
    let c_held = b_held.clone();
    // A, once B forwards B's change back, holds the same set.
    let a_held = b_held.clone();

    // C obtained A's changes without ever connecting to A.
    for change in [a1, a2, a3] {
        assert!(c_held.contains(&change), "C must hold A's change {change} via B");
    }

    let a_state = batch_fold(&dag, &a_held);
    let c_state = batch_fold(&dag, &c_held);
    assert_eq!(a_state, c_state, "C must converge to A's state through B");

    // The concurrent f.txt edit (a2 vs b1) yields a winner at f.txt and a
    // conflict copy — and A and C, which never spoke, agree on both.
    assert!(c_state.contains_key("f.txt"), "the surviving f.txt content must be present");
    let conflict_copies: Vec<&String> =
        c_state.keys().filter(|k| k.contains("(conflicted copy,")).collect();
    assert_eq!(
        conflict_copies.len(),
        1,
        "exactly one conflict copy for the concurrent f.txt edit: {:?}",
        c_state.keys().collect::<Vec<_>>()
    );
    // g.txt (no conflict) survives untouched at version 3.
    assert_eq!(c_state.get("g.txt"), Some(&3));
}

/// A focused idempotence check: re-delivering an already-applied change, and
/// replaying the whole set after a simulated crash, never changes the state.
#[test]
fn crash_restart_replay_is_idempotent() {
    for seed in 0..64u64 {
        let sim: Simulation = simulate(seed);
        let reference = batch_fold(&sim.dag, &sim.all_changes);
        let mut rng = StdRng::seed_from_u64(seed ^ 0xC0FFEE);

        // Deliver, then "crash" and replay from scratch in a new order with
        // duplicates — the recovered state must match.
        let mut order: Vec<usize> = sim.all_changes.iter().copied().collect();
        permute_with_dups(&mut rng, &mut order);
        let mut engine = Incremental::new(&sim.dag);
        for &c in &order {
            engine.deliver(c);
        }
        let before = engine.materialize();

        let mut replay: Vec<usize> = sim.all_changes.iter().copied().collect();
        permute_with_dups(&mut rng, &mut replay);
        let mut recovered = Incremental::new(&sim.dag);
        for &c in &replay {
            recovered.deliver(c);
        }
        assert_eq!(before, recovered.materialize(), "seed {seed}: replay changed state");
        assert_eq!(before, reference, "seed {seed}: incremental state != reference fold");
    }
}

/// Per-device initial import of the same tree creates a concurrent root on
/// every device. Because the roots carry byte-identical content, they collapse
/// to one equivalence class per path and produce ZERO conflict copies — the
/// upgrade path must not turn "everyone already has the same files" into a copy
/// storm.
#[test]
fn identical_initial_imports_produce_no_conflict_copies() {
    for device_count in 2..=4u8 {
        let mut dag = Dag::new();
        let tree = [("a.txt", 1u64), ("b.txt", 2), ("notes/c.txt", 3)];
        let mut all = BTreeSet::new();
        for dev in 0..device_count {
            let ops: Vec<Op> =
                tree.iter().map(|(p, v)| Op::Put { path: p.to_string(), version: *v }).collect();
            all.insert(dag.append(dev, Vec::new(), ops));
        }
        let state = batch_fold(&dag, &all);
        let copies: Vec<&String> =
            state.keys().filter(|k| k.contains("(conflicted copy,")).collect();
        assert!(
            copies.is_empty(),
            "device_count {device_count}: identical imports produced conflict copies: {copies:?}"
        );
        for (p, v) in &tree {
            assert_eq!(state.get(*p), Some(v), "device_count {device_count}: {p}");
        }
        assert_eq!(state.len(), tree.len(), "device_count {device_count}: exactly the tree");
    }
}

/// The nested-overlap corner the engine unification closes: a conflict-copy
/// path is itself independently edited with fresh concurrency. The
/// incrementally-maintained state must still equal the batch fold.
#[test]
fn conflict_copy_path_independently_edited_converges() {
    let mut dag = Dag::new();
    // Concurrent roots create a conflict copy at "f.txt".
    let a = dag.append(0, Vec::new(), vec![Op::Put { path: "f.txt".into(), version: 1 }]);
    let b = dag.append(1, Vec::new(), vec![Op::Put { path: "f.txt".into(), version: 2 }]);
    let base: BTreeSet<usize> = [a, b].into_iter().collect();
    let copy_path = batch_fold(&dag, &base)
        .into_keys()
        .find(|k| k.contains("(conflicted copy,"))
        .expect("concurrent roots produce a conflict copy");
    // Two devices that have seen both roots concurrently edit the copy path
    // itself with fresh, different content.
    let c = dag.append(0, vec![a, b], vec![Op::Put { path: copy_path.clone(), version: 3 }]);
    let d = dag.append(1, vec![a, b], vec![Op::Put { path: copy_path.clone(), version: 4 }]);
    let all: BTreeSet<usize> = [a, b, c, d].into_iter().collect();
    let reference = batch_fold(&dag, &all);
    for seed in 0..16u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut order: Vec<usize> = all.iter().copied().collect();
        permute_with_dups(&mut rng, &mut order);
        let mut eng = Incremental::new(&dag);
        for x in &order {
            eng.deliver(*x);
        }
        assert_eq!(
            eng.materialize(),
            reference,
            "seed {seed}: incremental != batch on the nested-overlap corner"
        );
    }
    // The copy path survives with one of the fresh edits, and fresh concurrency
    // at it yields a further conflict copy of the loser.
    assert!(reference.contains_key(&copy_path), "the independently-edited copy path holds content");
    let copies = reference.keys().filter(|k| k.contains("(conflicted copy,")).count();
    assert!(copies >= 2, "fresh concurrency at the copy path yields a deeper copy: {reference:?}");
}

fn assert_incremental_matches(dag: &Dag, all: &BTreeSet<usize>) {
    let reference = batch_fold(dag, all);
    let mut rng = StdRng::seed_from_u64(7);
    let mut order: Vec<usize> = all.iter().copied().collect();
    permute_with_dups(&mut rng, &mut order);
    let mut eng = Incremental::new(dag);
    for x in &order {
        eng.deliver(*x);
    }
    assert_eq!(eng.materialize(), reference, "incremental != batch");
}

/// A `Move` is a hint: the fold desugars it to `Delete{from}` + `Create{to}`
/// and resolves the desugared ops per path (there is no special Move-vs-Move
/// rule). These are the ugly Move corners.
#[test]
fn move_desugars_to_delete_plus_create() {
    // (a) Concurrent moves of one file to two destinations: the source
    // disappears, both destinations exist, and there is NO conflict copy
    // (distinct target paths, each with a single content head).
    {
        let mut dag = Dag::new();
        let root = dag.append(0, Vec::new(), vec![Op::Put { path: "f.txt".into(), version: 1 }]);
        let g = dag.append(
            0,
            vec![root],
            vec![Op::Mov { from: "f.txt".into(), to: "g.txt".into(), version: 1 }],
        );
        let h = dag.append(
            1,
            vec![root],
            vec![Op::Mov { from: "f.txt".into(), to: "h.txt".into(), version: 1 }],
        );
        let all: BTreeSet<usize> = [root, g, h].into_iter().collect();
        let state = batch_fold(&dag, &all);
        assert!(!state.contains_key("f.txt"), "source gone: {state:?}");
        assert_eq!(state.get("g.txt"), Some(&1));
        assert_eq!(state.get("h.txt"), Some(&1));
        assert!(
            state.keys().all(|k| !k.contains("(conflicted copy,")),
            "distinct move targets produce no conflict copy: {state:?}"
        );
        assert_incremental_matches(&dag, &all);
    }
    // (b) Move-vs-edit: A moves f->g, B concurrently edits f. Desugared per
    // path, the edit survives at the source (content beats the move's tombstone
    // there) and the moved content lands at the destination — both survive.
    {
        let mut dag = Dag::new();
        let root = dag.append(0, Vec::new(), vec![Op::Put { path: "f.txt".into(), version: 1 }]);
        let mv = dag.append(
            0,
            vec![root],
            vec![Op::Mov { from: "f.txt".into(), to: "g.txt".into(), version: 1 }],
        );
        let edit = dag.append(1, vec![root], vec![Op::Put { path: "f.txt".into(), version: 2 }]);
        let all: BTreeSet<usize> = [root, mv, edit].into_iter().collect();
        let state = batch_fold(&dag, &all);
        assert_eq!(
            state.get("f.txt"),
            Some(&2),
            "concurrent edit survives at the source: {state:?}"
        );
        assert_eq!(state.get("g.txt"), Some(&1), "move lands at the destination: {state:?}");
        assert_incremental_matches(&dag, &all);
    }
    // (c) Case-only rename f.txt -> F.txt: at the model level two distinct
    // paths — source gone, destination present.
    {
        let mut dag = Dag::new();
        let root = dag.append(0, Vec::new(), vec![Op::Put { path: "f.txt".into(), version: 1 }]);
        let ren = dag.append(
            0,
            vec![root],
            vec![Op::Mov { from: "f.txt".into(), to: "F.txt".into(), version: 1 }],
        );
        let all: BTreeSet<usize> = [root, ren].into_iter().collect();
        let state = batch_fold(&dag, &all);
        assert!(!state.contains_key("f.txt"), "old case gone: {state:?}");
        assert_eq!(state.get("F.txt"), Some(&1), "new case present: {state:?}");
        assert_incremental_matches(&dag, &all);
    }
}
