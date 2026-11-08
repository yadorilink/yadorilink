//! What projecting a provider root's obligations has to do, as a value.
//!
//! A provider root has no directory, so its projector writes `files` rows and
//! nothing else. For the names of one level that have an open obligation, the
//! level's native plan decides every row: [`provider_actions`] turns the plan
//! into the rows to write and the rows to retire, and the projector only
//! executes them in order.
//!
//! A plan node at a path always stands for that same path (the head's source
//! path is the path it is keyed by), so a name's row is the node planned at the
//! name itself: the same reading a pass over a plain root takes of that path
//! (see the differential test).

use std::collections::BTreeSet;

use crate::ids::SyncPath;
use crate::native_plan::{NativeLevelPlan, NativeLocatedHead, NativePlannedNode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProviderAction {
    /// Make the row at `physical` show `head`.
    WriteRow { physical: SyncPath, head: NativeLocatedHead },
    /// The plan holds no head for the path any more: retire its row.
    /// `structural`: the plan still holds a directory there only because
    /// something below it is live, so a retired explicit directory becomes a
    /// structural one.
    Retire { source: String, structural: bool },
}

/// The actions for `names`, in the order they are executed: per name, the row of the node
/// planned at it, or its retirement when the plan holds no head there.
pub fn provider_actions(names: &BTreeSet<String>, plan: &NativeLevelPlan) -> Vec<ProviderAction> {
    let mut actions = Vec::new();
    for name in names {
        match plan.nodes.get(&SyncPath(name.clone())) {
            Some(
                NativePlannedNode::Entry { head, .. }
                | NativePlannedNode::ExplicitDirectory { head },
            ) => {
                debug_assert_eq!(head.source_path.as_str(), name, "a node stands for its own path");
                actions.push(ProviderAction::WriteRow {
                    physical: SyncPath(name.clone()),
                    head: head.clone(),
                });
            }
            other => actions.push(ProviderAction::Retire {
                source: name.clone(),
                structural: matches!(other, Some(NativePlannedNode::StructuralDirectory)),
            }),
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convergence_plan::tests::{entry, head, universe, Rng};
    use crate::convergence_plan::{
        parent_of, plan_pass, LevelRead, Observation, PassInput, PlannedWork,
    };
    use std::collections::BTreeMap;

    /// The physical path -> head map the actions leave standing, for tests that
    /// compare the provider view with the plain-root one.
    fn rows_written(actions: &[ProviderAction]) -> BTreeMap<&SyncPath, &NativeLocatedHead> {
        actions
            .iter()
            .filter_map(|a| match a {
                ProviderAction::WriteRow { physical, head } => Some((physical, head)),
                ProviderAction::Retire { .. } => None,
            })
            .collect()
    }

    fn names(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|p| (*p).to_owned()).collect()
    }

    fn plan(nodes: Vec<(&str, NativePlannedNode)>) -> NativeLevelPlan {
        NativeLevelPlan {
            nodes: nodes.into_iter().map(|(p, n)| (SyncPath(p.into()), n)).collect(),
            contested: Default::default(),
        }
    }

    #[test]
    fn a_name_writes_the_row_planned_at_it_or_retires() {
        let plan = plan(vec![("a", entry("a")), ("b", NativePlannedNode::StructuralDirectory)]);
        let actions = provider_actions(&names(&["a", "b", "c"]), &plan);
        let shape: Vec<_> = actions
            .iter()
            .map(|a| match a {
                ProviderAction::WriteRow { physical, .. } => format!("write {}", physical.as_str()),
                ProviderAction::Retire { source, structural } => {
                    format!("retire {source} structural={structural}")
                }
            })
            .collect();
        assert_eq!(shape, ["write a", "retire b structural=true", "retire c structural=false"]);
    }

    /// Every name in a random level gets exactly the action its plan implies, stated apart from
    /// the implementation: a row for a head planned at it, otherwise a retirement, structural
    /// iff a structural directory is planned there.
    #[test]
    fn random_levels_yield_the_actions_their_plan_implies() {
        for seed in 0..3000u64 {
            let mut rng = Rng(seed);
            let (plan, wanted) = random_level(&mut rng);
            let actions = provider_actions(&wanted, &plan);
            assert_eq!(actions.len(), wanted.len(), "seed {seed}");
            for (name, action) in wanted.iter().zip(&actions) {
                let expected = match plan.nodes.get(&SyncPath(name.clone())) {
                    Some(
                        NativePlannedNode::Entry { head, .. }
                        | NativePlannedNode::ExplicitDirectory { head },
                    ) => ProviderAction::WriteRow {
                        physical: SyncPath(name.clone()),
                        head: head.clone(),
                    },
                    Some(NativePlannedNode::StructuralDirectory) => {
                        ProviderAction::Retire { source: name.clone(), structural: true }
                    }
                    None => ProviderAction::Retire { source: name.clone(), structural: false },
                };
                assert_eq!(action, &expected, "seed {seed} {name}");
            }
        }
    }

    /// A random single level (the root) and a random subset of its children as the names.
    fn random_level(rng: &mut Rng) -> (NativeLevelPlan, BTreeSet<String>) {
        let children: Vec<String> =
            universe().into_iter().filter(|p| parent_of(p).is_empty()).collect();
        let mut nodes = BTreeMap::new();
        for child in &children {
            let node = match rng.below(6) {
                0 | 1 => continue,
                2 => NativePlannedNode::StructuralDirectory,
                3 => NativePlannedNode::ExplicitDirectory { head: head(child, 1) },
                _ => entry(child),
            };
            nodes.insert(SyncPath(child.clone()), node);
        }
        let wanted = children.iter().filter(|_| rng.chance(60)).cloned().collect();
        (NativeLevelPlan { nodes, contested: Default::default() }, wanted)
    }

    /// The provider view and a pass over a plain root read the same plan the same way: every row
    /// the provider writes for a path is the head a pass would settle that path from, and a name
    /// the provider retires is one a pass finds no head for (or only a structural directory).
    #[test]
    fn the_provider_view_and_the_plain_root_pass_agree_on_every_path() {
        for seed in 0..3000u64 {
            let mut rng = Rng(seed);
            let (level, wanted) = random_level(&mut rng);
            let actions = provider_actions(&wanted, &level);
            let levels = BTreeMap::from([(String::new(), LevelRead::Planned(level))]);
            let pass = plan_pass(&PassInput {
                seeds: &wanted,
                levels: &levels,
                observation: Observation { frozen: false, ignored: &|_| false, paused: &|_| false },
            });
            let work = |path: &str| pass.actions.iter().find(|a| a.path == path).map(|a| &a.work);
            for action in &actions {
                match action {
                    ProviderAction::WriteRow { physical, head } => match work(physical.as_str()) {
                        Some(PlannedWork::Settle(
                            NativePlannedNode::Entry { head: h, .. }
                            | NativePlannedNode::ExplicitDirectory { head: h },
                        )) => assert_eq!(h, head, "seed {seed} {}", physical.as_str()),
                        other => panic!("seed {seed} {}: {other:?}", physical.as_str()),
                    },
                    ProviderAction::Retire { source, structural } => match work(source) {
                        Some(PlannedWork::SettleAbsent) => assert!(!structural, "seed {seed}"),
                        Some(PlannedWork::Settle(NativePlannedNode::StructuralDirectory)) => {
                            assert!(structural, "seed {seed}")
                        }
                        other => panic!("seed {seed} retire {source}: {other:?}"),
                    },
                }
            }
            // And the other way: a path a pass settles from a head is a row the provider writes.
            for a in &pass.actions {
                if let PlannedWork::Settle(
                    NativePlannedNode::Entry { head, .. }
                    | NativePlannedNode::ExplicitDirectory { head },
                ) = &a.work
                {
                    if wanted.contains(&a.path) {
                        assert!(
                            rows_written(&actions).get(&SyncPath(a.path.clone())) == Some(&head),
                            "seed {seed} {}",
                            a.path
                        );
                    }
                }
            }
        }
    }
}
