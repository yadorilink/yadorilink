#![cfg(test)]

use super::*;

#[test]
fn action_counts_tallies_every_variant_separately() {
    let plan = RewindPlan {
        group_id: "g".into(),
        target_unix_nanos: 100,
        entries: vec![
            RewindPathEntry {
                path: "a".into(),
                current_version_seq: 1,
                current_version_hash: VersionHash([0u8; 32]),
                action: RewindPathAction::Create {
                    version_seq: 1,
                    version_hash: VersionHash([1u8; 32]),
                },
            },
            RewindPathEntry {
                path: "b".into(),
                current_version_seq: 1,
                current_version_hash: VersionHash([0u8; 32]),
                action: RewindPathAction::Delete,
            },
            RewindPathEntry {
                path: "c".into(),
                current_version_seq: 1,
                current_version_hash: VersionHash([0u8; 32]),
                action: RewindPathAction::Replace {
                    to_version_seq: 1,
                    to_version_hash: VersionHash([2u8; 32]),
                },
            },
            RewindPathEntry {
                path: "d".into(),
                current_version_seq: 1,
                current_version_hash: VersionHash([0u8; 32]),
                action: RewindPathAction::Unchanged,
            },
            RewindPathEntry {
                path: "e".into(),
                current_version_seq: 1,
                current_version_hash: VersionHash([0u8; 32]),
                action: RewindPathAction::Unavailable {
                    reason: RewindUnavailableReason::RemovedByRetention,
                },
            },
            RewindPathEntry {
                path: "f".into(),
                current_version_seq: 1,
                current_version_hash: VersionHash([0u8; 32]),
                action: RewindPathAction::Unchanged,
            },
        ],
        rename_candidates: Vec::new(),
    };
    assert_eq!(
        plan.action_counts(),
        RewindActionCounts { create: 1, delete: 1, replace: 1, unchanged: 2, unavailable: 1 }
    );
}

/// An `Unavailable` path must never be counted as, or collapse into,
/// `Unchanged`: the whole point of the variant is that "no answer
/// exists" is reported as itself.
#[test]
fn unavailable_is_never_tallied_as_unchanged() {
    let plan = RewindPlan {
        group_id: "g".into(),
        target_unix_nanos: 0,
        entries: vec![RewindPathEntry {
            path: "a".into(),
            current_version_seq: 1,
            current_version_hash: VersionHash([0u8; 32]),
            action: RewindPathAction::Unavailable { reason: RewindUnavailableReason::NoHistory },
        }],
        rename_candidates: Vec::new(),
    };
    let counts = plan.action_counts();
    assert_eq!(counts.unavailable, 1);
    assert_eq!(counts.unchanged, 0);
}

fn entry(path: &str, current_version_seq: i64, action: RewindPathAction) -> RewindPathEntry {
    RewindPathEntry {
        path: path.into(),
        current_version_seq,
        current_version_hash: VersionHash([current_version_seq as u8; 32]),
        action,
    }
}

/// A named change to a plan, applied to a fresh [`sample_plan`].
type PlanEdit = Box<dyn Fn(&mut RewindPlan)>;

fn sample_plan() -> RewindPlan {
    RewindPlan {
        group_id: "g".into(),
        target_unix_nanos: 500,
        entries: vec![
            entry(
                "a",
                4,
                RewindPathAction::Create { version_seq: 3, version_hash: VersionHash([1u8; 32]) },
            ),
            entry("b", 2, RewindPathAction::Delete),
            entry(
                "c",
                5,
                RewindPathAction::Replace {
                    to_version_seq: 1,
                    to_version_hash: VersionHash([2u8; 32]),
                },
            ),
            entry("d", 7, RewindPathAction::Unchanged),
            entry(
                "e",
                9,
                RewindPathAction::Unavailable {
                    reason: RewindUnavailableReason::RemovedByRetention,
                },
            ),
        ],
        rename_candidates: Vec::new(),
    }
}

/// The id is a function of the plan's content, not of how the entries
/// happen to be ordered in memory.
#[test]
fn the_same_plan_has_the_same_id_in_any_entry_order() {
    let plan = sample_plan();
    let mut shuffled = plan.clone();
    shuffled.entries.reverse();
    shuffled.entries.swap(0, 2);
    assert_eq!(plan.plan_id(), plan.clone().plan_id());
    assert_eq!(plan.plan_id(), shuffled.plan_id());
}

/// Every field that changes what an execution would do changes the id.
#[test]
fn the_id_changes_with_every_field_an_execution_acts_on() {
    let base = sample_plan().plan_id();
    let variants: Vec<(&str, PlanEdit)> = vec![
        ("group", Box::new(|p| p.group_id = "h".into())),
        ("target", Box::new(|p| p.target_unix_nanos = 501)),
        ("path", Box::new(|p| p.entries[1].path = "b2".into())),
        ("action", Box::new(|p| p.entries[1].action = RewindPathAction::Unchanged)),
        (
            "unchanged becomes actionable",
            Box::new(|p| p.entries[3].action = RewindPathAction::Delete),
        ),
        ("delete current seq", Box::new(|p| p.entries[1].current_version_seq = 3)),
        ("replace current seq", Box::new(|p| p.entries[2].current_version_seq = 6)),
        ("create current seq", Box::new(|p| p.entries[0].current_version_seq = 5)),
        (
            "delete current hash",
            Box::new(|p| p.entries[1].current_version_hash = VersionHash([8u8; 32])),
        ),
        (
            "replace current hash",
            Box::new(|p| p.entries[2].current_version_hash = VersionHash([8u8; 32])),
        ),
        (
            "create version",
            Box::new(|p| {
                p.entries[0].action = RewindPathAction::Create {
                    version_seq: 2,
                    version_hash: VersionHash([1u8; 32]),
                }
            }),
        ),
        (
            "create hash",
            Box::new(|p| {
                p.entries[0].action = RewindPathAction::Create {
                    version_seq: 3,
                    version_hash: VersionHash([9u8; 32]),
                }
            }),
        ),
        (
            "replace version",
            Box::new(|p| {
                p.entries[2].action = RewindPathAction::Replace {
                    to_version_seq: 2,
                    to_version_hash: VersionHash([2u8; 32]),
                }
            }),
        ),
        (
            "replace hash",
            Box::new(|p| {
                p.entries[2].action = RewindPathAction::Replace {
                    to_version_seq: 1,
                    to_version_hash: VersionHash([9u8; 32]),
                }
            }),
        ),
        ("added path", Box::new(|p| p.entries.push(entry("f", 1, RewindPathAction::Delete)))),
        ("removed path", Box::new(|p| drop(p.entries.remove(1)))),
    ];
    for (name, mutate) in variants {
        let mut plan = sample_plan();
        mutate(&mut plan);
        assert_ne!(plan.plan_id(), base, "changing the {name} must change the plan id");
    }
}

/// Nothing an execution would not act on is part of the identity: the
/// paths it leaves alone, the advisory rename list, and prose.
#[test]
fn the_id_ignores_what_an_execution_does_not_act_on() {
    let base = sample_plan().plan_id();
    let variants: Vec<(&str, PlanEdit)> = vec![
        ("unchanged current seq", Box::new(|p| p.entries[3].current_version_seq = 8)),
        (
            "unchanged current hash",
            Box::new(|p| p.entries[3].current_version_hash = VersionHash([8u8; 32])),
        ),
        (
            "added unchanged path",
            Box::new(|p| p.entries.push(entry("f", 1, RewindPathAction::Unchanged))),
        ),
        (
            "unavailable reason",
            Box::new(|p| {
                p.entries[4].action =
                    RewindPathAction::Unavailable { reason: RewindUnavailableReason::JoinedAfter }
            }),
        ),
        (
            "rename candidate",
            Box::new(|p| {
                p.rename_candidates.push(RewindRenameCandidate {
                    from_path: "b".into(),
                    to_path: "a".into(),
                    version_hash: VersionHash([1u8; 32]),
                })
            }),
        ),
    ];
    for (name, mutate) in variants {
        let mut plan = sample_plan();
        mutate(&mut plan);
        assert_eq!(plan.plan_id(), base, "changing the {name} must not change the plan id");
    }
}
