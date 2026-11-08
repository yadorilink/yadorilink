//! The ordered work of one convergence pass, as a value.
//!
//! [`plan_pass`] is pure: its input is the per-level native plans a pass read
//! plus a snapshot of what the device observes about the group (frozen,
//! ignored, paused), and its output is the actions in the order they are to be
//! run. It holds no I/O and no clock, so the same input is the same plan.
//!
//! What it decides:
//!
//! * which paths the pass works on: every planned node that a seed or an
//!   ancestor of a seed is, and every seed the plan holds nothing for;
//! * which seeds cannot be worked on at all (contested, or on a level that
//!   could not be planned) and so are retried;
//! * the order: at each depth directories, then entries; paths the plan holds
//!   nothing for last, deepest first;
//! * the gate that depends only on the snapshot: ignored paths settle without
//!   work, paths that are paused, frozen, or below a contested path wait.
//!
//! What it does not decide: anything that depends on what an earlier action of
//! the same pass turned out to be (a directory that could not be shaped
//! declines what is below it). The executor keeps that.

use std::collections::{BTreeMap, BTreeSet};

use crate::native_plan::{NativeLevelPlan, NativePlannedNode};

/// A level of the group's tree: its directory path, `""` for the root.
pub type LevelPath = String;

/// What reading one level's plan produced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LevelRead {
    Planned(NativeLevelPlan),
    /// A live head whose version record has not arrived: nothing about the
    /// level may be taken as absent.
    Unplannable,
}

/// What the device observes about the group at the time of the pass.
pub struct Observation<'a> {
    /// A rebootstrap holds the whole group still.
    pub frozen: bool,
    /// Excluded by this device's ignore set.
    pub ignored: &'a dyn Fn(&str) -> bool,
    /// Covered by a paused or held item.
    pub paused: &'a dyn Fn(&str) -> bool,
}

pub struct PassInput<'a> {
    pub seeds: &'a BTreeSet<String>,
    /// The plan of every level the seeds and their ancestors live on.
    pub levels: &'a BTreeMap<LevelPath, LevelRead>,
    pub observation: Observation<'a>,
}

/// What a pass does at one path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PlannedWork {
    /// Make the path what the plan's node says.
    Settle(NativePlannedNode),
    /// The plan holds nothing for the path.
    SettleAbsent,
}

/// What the observation allows of the work at a path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PlannedGate {
    Open,
    /// Settled without work: this device ignores the path.
    Ignored,
    /// Left for a later attempt.
    Declined,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlannedAction {
    pub path: String,
    pub work: PlannedWork,
    pub gate: PlannedGate,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PassPlan {
    /// In the order to run.
    pub actions: Vec<PlannedAction>,
    /// Seeds nothing can be done for in this pass.
    pub retry: BTreeSet<String>,
    /// Paths of the planned levels that are contested.
    pub contested: BTreeSet<String>,
}

/// `path`'s parent, `""` for a path at the root.
pub fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Every directory above `path`, nearest first.
pub fn proper_ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(path.rsplit_once('/').map(|(parent, _)| parent), |p| {
        p.rsplit_once('/').map(|(parent, _)| parent)
    })
}

/// Position in a pass: shallow first; directories, then entries; paths the
/// plan holds nothing for after everything, deep first.
fn rank(path: &str, work: &PlannedWork) -> (u8, usize, u8) {
    let depth = path.matches('/').count();
    match work {
        PlannedWork::SettleAbsent => (1, usize::MAX - depth, 0),
        PlannedWork::Settle(
            NativePlannedNode::StructuralDirectory | NativePlannedNode::ExplicitDirectory { .. },
        ) => (0, depth, 0),
        PlannedWork::Settle(NativePlannedNode::Entry { .. }) => (0, depth, 1),
    }
}

/// The levels a pass over `seeds` reads: each seed's, and its ancestors'.
pub fn levels_of(seeds: &BTreeSet<String>) -> BTreeSet<LevelPath> {
    let mut levels = BTreeSet::new();
    for path in seeds {
        levels.insert(parent_of(path).to_owned());
        for ancestor in proper_ancestors(path) {
            levels.insert(parent_of(ancestor).to_owned());
        }
    }
    levels
}

/// The names of `seeds` and their ancestors: those a pass is about.
pub fn interesting_names(seeds: &BTreeSet<String>) -> BTreeSet<&str> {
    seeds.iter().map(String::as_str).chain(seeds.iter().flat_map(|p| proper_ancestors(p))).collect()
}

pub fn plan_pass(input: &PassInput<'_>) -> PassPlan {
    let interesting = interesting_names(input.seeds);
    let mut contested = BTreeSet::new();
    let mut work: BTreeMap<String, PlannedWork> = BTreeMap::new();
    for read in input.levels.values() {
        let LevelRead::Planned(plan) = read else { continue };
        contested.extend(plan.contested.iter().map(|p| p.as_str().to_owned()));
        for (path, node) in &plan.nodes {
            if interesting.contains(path.as_str()) {
                work.insert(path.as_str().to_owned(), PlannedWork::Settle(node.clone()));
            }
        }
    }

    let mut retry = BTreeSet::new();
    for path in input.seeds {
        if work.contains_key(path) {
            continue;
        }
        if contested.contains(path)
            || matches!(input.levels.get(parent_of(path)), Some(LevelRead::Unplannable))
        {
            retry.insert(path.clone());
        } else {
            work.insert(path.clone(), PlannedWork::SettleAbsent);
        }
    }

    let mut ordered: Vec<(String, PlannedWork)> = work.into_iter().collect();
    ordered.sort_by_key(|(path, work)| (rank(path, work), path.clone()));
    let actions = ordered
        .into_iter()
        .map(|(path, work)| {
            let gate = gate_of(&input.observation, &contested, &path);
            PlannedAction { path, work, gate }
        })
        .collect();
    PassPlan { actions, retry, contested }
}

fn gate_of(observation: &Observation<'_>, contested: &BTreeSet<String>, path: &str) -> PlannedGate {
    if (observation.ignored)(path) {
        return PlannedGate::Ignored;
    }
    if (observation.paused)(path)
        || observation.frozen
        || proper_ancestors(path).any(|ancestor| contested.contains(ancestor))
    {
        return PlannedGate::Declined;
    }
    PlannedGate::Open
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::author::{AuthorId, IncarnationId};
    use crate::file::RecordKind;
    use crate::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
    use crate::native_plan::NativeLocatedHead;
    use crate::native_state::{DeltaHash, Dot, HeadPayload, LiveHead};

    pub fn head(path: &str, seq: u64) -> NativeLocatedHead {
        NativeLocatedHead {
            source_path: SyncPath(path.into()),
            head: LiveHead {
                dot: Dot {
                    author: AuthorId {
                        device: DeviceId("d".into()),
                        incarnation: IncarnationId([1; 16]),
                    },
                    seq: AuthorSeq(seq),
                },
                payload: HeadPayload {
                    version: VersionHash([seq as u8; 32]),
                    provenance: DeltaHash([2; 32]),
                },
            },
        }
    }

    pub fn entry(path: &str) -> NativePlannedNode {
        NativePlannedNode::Entry { head: head(path, 1), kind: RecordKind::File }
    }

    pub fn level(nodes: &[(&str, NativePlannedNode)], contested: &[&str]) -> LevelRead {
        LevelRead::Planned(NativeLevelPlan {
            nodes: nodes.iter().map(|(p, n)| (SyncPath((*p).into()), n.clone())).collect(),
            contested: contested.iter().map(|p| SyncPath((*p).into())).collect(),
        })
    }

    fn open_observation() -> Observation<'static> {
        Observation { frozen: false, ignored: &|_| false, paused: &|_| false }
    }

    fn seeds(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| (*p).to_owned()).collect()
    }

    fn paths(plan: &PassPlan) -> Vec<&str> {
        plan.actions.iter().map(|a| a.path.as_str()).collect()
    }

    #[test]
    fn directories_precede_entries_and_absent_paths_come_last_deepest_first() {
        let seeds = seeds(&["a/b/f", "a/g", "gone", "a/gone2"]);
        let mut levels = BTreeMap::new();
        levels.insert(String::new(), level(&[("a", NativePlannedNode::StructuralDirectory)], &[]));
        levels.insert(
            "a".into(),
            level(&[("a/b", NativePlannedNode::StructuralDirectory), ("a/g", entry("a/g"))], &[]),
        );
        levels.insert("a/b".into(), level(&[("a/b/f", entry("a/b/f"))], &[]));
        let plan = plan_pass(&PassInput {
            seeds: &seeds,
            levels: &levels,
            observation: open_observation(),
        });
        assert_eq!(paths(&plan), ["a", "a/b", "a/g", "a/b/f", "a/gone2", "gone"]);
        assert!(plan.retry.is_empty());
    }

    #[test]
    fn contested_and_unplannable_seeds_retry_and_hold_back_what_is_below() {
        let seeds = seeds(&["c", "c/x", "u/y", "ok"]);
        let mut levels = BTreeMap::new();
        levels.insert(String::new(), level(&[("ok", entry("ok"))], &["c"]));
        levels.insert("c".into(), level(&[("c/x", entry("c/x"))], &[]));
        levels.insert("u".into(), LevelRead::Unplannable);
        let plan = plan_pass(&PassInput {
            seeds: &seeds,
            levels: &levels,
            observation: open_observation(),
        });
        assert_eq!(plan.retry, super::tests::seeds(&["c", "u/y"]));
        let gate = |p: &str| plan.actions.iter().find(|a| a.path == p).unwrap().gate.clone();
        assert_eq!(gate("c/x"), PlannedGate::Declined);
        assert_eq!(gate("ok"), PlannedGate::Open);
    }

    #[test]
    fn the_observation_gates_ignored_before_paused_and_frozen_declines_all() {
        let seeds = seeds(&["a", "b", "c"]);
        let mut levels = BTreeMap::new();
        levels.insert(
            String::new(),
            level(&[("a", entry("a")), ("b", entry("b")), ("c", entry("c"))], &[]),
        );
        let observation = Observation {
            frozen: false,
            ignored: &|p| p == "a",
            paused: &|p| p == "a" || p == "b",
        };
        let plan = plan_pass(&PassInput { seeds: &seeds, levels: &levels, observation });
        let gates: Vec<_> = plan.actions.iter().map(|a| a.gate.clone()).collect();
        assert_eq!(gates, [PlannedGate::Ignored, PlannedGate::Declined, PlannedGate::Open]);
        let frozen = Observation { frozen: true, ..open_observation() };
        let plan = plan_pass(&PassInput { seeds: &seeds, levels: &levels, observation: frozen });
        assert!(plan.actions.iter().all(|a| a.gate == PlannedGate::Declined));
    }

    /// splitmix64: a fixed, dependency-free source of random choices.
    pub(crate) struct Rng(pub(crate) u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        pub(crate) fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        pub(crate) fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }
    }

    /// Every path of depth 1..=3 over the names `a`, `b`, `c`.
    pub(crate) fn universe() -> Vec<String> {
        let mut all = Vec::new();
        let mut level = vec![String::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for parent in &level {
                for name in ["a", "b", "c"] {
                    next.push(if parent.is_empty() {
                        name.into()
                    } else {
                        format!("{parent}/{name}")
                    });
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    struct Case {
        seeds: BTreeSet<String>,
        levels: BTreeMap<LevelPath, LevelRead>,
        ignored: BTreeSet<String>,
        paused: BTreeSet<String>,
        frozen: bool,
    }

    fn random_case(rng: &mut Rng) -> Case {
        let universe = universe();
        let mut seeds = BTreeSet::new();
        for _ in 0..1 + rng.below(6) {
            seeds.insert(universe[rng.below(universe.len() as u64) as usize].clone());
        }
        let mut levels = BTreeMap::new();
        for level in levels_of(&seeds) {
            if rng.chance(8) {
                levels.insert(level, LevelRead::Unplannable);
                continue;
            }
            let mut nodes = BTreeMap::new();
            let mut contested = BTreeSet::new();
            for child in universe.iter().filter(|p| parent_of(p) == level) {
                let node = match rng.below(7) {
                    0 | 1 => continue,
                    2 => {
                        contested.insert(SyncPath(child.clone()));
                        continue;
                    }
                    3 => NativePlannedNode::StructuralDirectory,
                    4 => NativePlannedNode::ExplicitDirectory { head: head(child, 1) },
                    _ => entry(child),
                };
                nodes.insert(SyncPath(child.clone()), node);
            }
            levels.insert(level, LevelRead::Planned(NativeLevelPlan { nodes, contested }));
        }
        let mut pick = |percent| {
            universe.iter().filter(|_| rng.chance(percent)).cloned().collect::<BTreeSet<_>>()
        };
        let ignored = pick(8);
        let paused = pick(8);
        Case { seeds, levels, ignored, paused, frozen: rng.chance(5) }
    }

    fn run(case: &Case) -> PassPlan {
        plan_pass(&PassInput {
            seeds: &case.seeds,
            levels: &case.levels,
            observation: Observation {
                frozen: case.frozen,
                ignored: &|p| case.ignored.contains(p),
                paused: &|p| case.paused.contains(p),
            },
        })
    }

    /// Position stated independently of `rank`: depth-major, directories before entries,
    /// absent paths after everything and deepest first.
    fn position(action: &PlannedAction) -> (u8, i64, u8) {
        let depth = action.path.split('/').count() as i64;
        match &action.work {
            PlannedWork::SettleAbsent => (1, -depth, 0),
            PlannedWork::Settle(NativePlannedNode::Entry { .. }) => (0, depth, 1),
            PlannedWork::Settle(_) => (0, depth, 0),
        }
    }

    fn check(case: &Case, plan: &PassPlan) {
        // Equal input, equal plan.
        assert_eq!(&run(case), plan);

        // Every seed is in exactly one of: an action, retry.
        for seed in &case.seeds {
            let acted = plan.actions.iter().filter(|a| &a.path == seed).count();
            let retried = usize::from(plan.retry.contains(seed));
            assert_eq!(acted + retried, 1, "seed {seed}: {acted} actions, retry {retried}");
        }
        assert!(plan.retry.iter().all(|p| case.seeds.contains(p)));

        // No path twice; every action is about a seed or an ancestor of one.
        let names = interesting_names(&case.seeds);
        let distinct: BTreeSet<_> = plan.actions.iter().map(|a| &a.path).collect();
        assert_eq!(distinct.len(), plan.actions.len());
        assert!(plan.actions.iter().all(|a| names.contains(a.path.as_str())));

        // The plan is the level's own node; a seed with none is absent.
        for action in &plan.actions {
            let node = match case.levels.get(parent_of(&action.path)) {
                Some(LevelRead::Planned(level)) => level.nodes.get(&SyncPath(action.path.clone())),
                _ => None,
            };
            match (&action.work, node) {
                (PlannedWork::Settle(planned), Some(level_node)) => assert_eq!(planned, level_node),
                (PlannedWork::SettleAbsent, None) => {
                    assert!(case.seeds.contains(&action.path), "{}", action.path)
                }
                other => panic!("{}: {other:?}", action.path),
            }
        }

        // Contested seeds, and seeds on a level that could not be planned, only retry.
        for seed in &case.seeds {
            let contested = plan.contested.contains(seed);
            let unplannable =
                matches!(case.levels.get(parent_of(seed)), Some(LevelRead::Unplannable));
            if contested || unplannable {
                assert!(plan.retry.contains(seed), "{seed}");
            }
        }

        // Order.
        let positions: Vec<_> =
            plan.actions.iter().map(|a| (position(a), a.path.clone())).collect();
        assert!(positions.windows(2).all(|w| w[0] <= w[1]), "{positions:?}");

        // Gate.
        for action in &plan.actions {
            let below_contested =
                proper_ancestors(&action.path).any(|a| plan.contested.contains(a));
            let expected = if case.ignored.contains(&action.path) {
                PlannedGate::Ignored
            } else if case.paused.contains(&action.path) || case.frozen || below_contested {
                PlannedGate::Declined
            } else {
                PlannedGate::Open
            };
            assert_eq!(action.gate, expected, "{}", action.path);
        }
    }

    #[test]
    fn random_passes_keep_the_plan_invariants() {
        for seed in 0..3000u64 {
            let mut rng = Rng(seed);
            let case = random_case(&mut rng);
            let plan = run(&case);
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&case, &plan)))
                .unwrap_or_else(|_| panic!("invariant broken for rng seed {seed}"));
        }
    }
}
