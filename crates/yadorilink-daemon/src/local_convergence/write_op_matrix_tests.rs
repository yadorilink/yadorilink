#![cfg(all(test, unix))]
//! The crash and fault matrix of the write operation: one row per lane, one
//! column per crash state (power cut) and per [`WriteOpFailpoint`] (fault).
//!
//! A lane that runs on the operation fills its cells; a lane that has not
//! migrated yet has documented empty cells naming the change that fills them,
//! so the matrix shows what is still unproven instead of hiding it. The
//! completeness test fails when a lane gains a state or a failpoint without a
//! cell, when a cell is filled twice, or when a filled power-cut cell runs a
//! scenario that does not cut in the state it claims.
//!
//! A new lane plugs in by adding its cells in [`power_cut_cell`] and
//! [`fault_cell`]: a power-cut cell returns the `power_cut_tests` scenarios
//! that cut the real lane in that state (the driver then runs the real
//! repair); a fault cell names the test that arms the failpoint, shows the
//! attempt stops there with the data intact, and shows the retry finishes.

use super::power_cut_tests::{
    base, run_scenario, Barrier, Cut, Scenario, Stage, UserEdit, EVERY_CUT,
};
use crate::write_op::failpoint::WriteOpFailpoint;
use crate::write_op::OpKind;
use yadorilink_replica_domain::crash_state::CrashState;

/// A write lane: one way a path is written, which runs on one [`OpKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lane {
    /// Eager receive of a file's content (full and deferred flush).
    A,
    /// Hydrate on demand.
    J,
    /// Repair reconstruct.
    M,
    /// Symlink and directory placement.
    EF,
    /// Tombstone delete.
    H,
}

impl Lane {
    const ALL: [Lane; 5] = [Lane::A, Lane::J, Lane::M, Lane::EF, Lane::H];

    fn kind(self) -> OpKind {
        match self {
            Lane::A | Lane::J | Lane::M => OpKind::Materialize,
            Lane::EF => OpKind::SingleObject,
            Lane::H => OpKind::Delete,
        }
    }

    /// The crash states a power cut can leave this lane's path in.
    fn states(self) -> &'static [CrashState] {
        use CrashState::*;
        match self {
            Lane::A | Lane::J | Lane::M => &[
                X0Idle,
                X1Prepared,
                X3RenamedUnrecorded,
                X4LandedDurable,
                X5ProvenFlushPending,
                X6ProvenObligationOpen,
                X7Diverged,
            ],
            Lane::EF => &[X0Idle, X1Prepared, X3RenamedUnrecorded, X4LandedDurable, X7Diverged],
            Lane::H => &[X0Idle, X8DeleteInFlight, X8bDeleteNotRemoved],
        }
    }
}

enum PowerCutCell {
    /// Scenarios that cut the real lane in this state.
    Cut(fn() -> Vec<Scenario>),
    /// Not driven yet: why, and which change fills it.
    Empty(&'static str),
}

enum FaultCell {
    /// The test, in the test file `source` (the text of the lane's own test module), that arms
    /// the point for this lane: the attempt stops there, the data is intact, and the retry (or
    /// the next pass) finishes. For a repair rebuild the point is the matching `RepairFailpoint`.
    Test {
        source: &'static str,
        name: &'static str,
    },
    Empty(&'static str),
}

const EAGER_TESTS: &str = include_str!("write_op_failpoint_tests.rs");
const HYDRATION_TESTS: &str = include_str!("../hydration/tests.rs");
const DELETE_TESTS: &str = include_str!("delete_projection_tests.rs");
const SYMLINK_TESTS: &str = include_str!("symlink_and_metadata_only_update_tests.rs");
const DIRECTORY_TESTS: &str = include_str!("ancestor_directory_tests.rs");
const REPAIR_TESTS: &str =
    include_str!("../replica_coordinator/materialization_execution/tests.rs");

const NO_STAGE_OR_BARRIER: &str = "the lane has no hook at this step: no separate stage, \
     observe or deferred flush barrier";

fn eager_empty(state: CrashState) -> PowerCutCell {
    use CrashState::*;
    PowerCutCell::Empty(match state {
        X4LandedDurable => {
            "the landed mark is set and the proof follows in one step in full mode; reachable only \
             with a cut inside the proof transaction"
        }
        X6ProvenObligationOpen => "the driver receives without an obligation claim",
        _ => "no scenario for this state",
    })
}

fn power_cut_cell(lane: Lane, state: CrashState) -> PowerCutCell {
    use CrashState::*;
    match (lane, state) {
        (Lane::A, X0Idle) => PowerCutCell::Cut(|| {
            let mut s = base(2, Stage::Committed, Barrier::Survives);
            s.flushed = vec![true; 2];
            vec![s]
        }),
        (Lane::A, X1Prepared) => PowerCutCell::Cut(|| {
            [Cut::New, Cut::Missing]
                .into_iter()
                .map(|cut| {
                    let mut s = base(2, Stage::BeforeRename, Barrier::Survives);
                    s.prior = true;
                    s.cuts = vec![cut; 2];
                    s
                })
                .collect()
        }),
        (Lane::A, X3RenamedUnrecorded) => PowerCutCell::Cut(|| {
            // A cut before the rename with no prior version: the name is missing.
            let mut all: Vec<Scenario> = [Cut::New, Cut::Missing]
                .into_iter()
                .map(|cut| {
                    let mut s = base(2, Stage::BeforeRename, Barrier::Survives);
                    s.cuts = vec![cut; 2];
                    s
                })
                .collect();
            all.extend(EVERY_CUT.into_iter().map(|cut| {
                let mut s = base(1, Stage::BeforeCommit, Barrier::Survives);
                s.cuts = vec![cut];
                s.prior = cut == Cut::Old;
                s
            }));
            for cut in [Cut::Missing, Cut::Old] {
                let mut s = base(2, Stage::Committed, Barrier::CutBeforeDirFlush);
                s.prior = cut == Cut::Old;
                s.flushed = vec![true; 2];
                s.cuts = vec![cut, Cut::New];
                all.push(s);
            }
            all
        }),
        (Lane::A, X5ProvenFlushPending) => PowerCutCell::Cut(|| {
            let mut cleared_never = base(2, Stage::Committed, Barrier::CutBeforeClear);
            cleared_never.flushed = vec![true; 2];
            let mut flush_failed = base(3, Stage::Committed, Barrier::Survives);
            flush_failed.flushed = vec![true, false, true];
            flush_failed.cuts = vec![Cut::New, Cut::Zero, Cut::New];
            vec![cleared_never, flush_failed]
        }),
        (Lane::A, X7Diverged) => PowerCutCell::Cut(|| {
            [UserEdit::SameSize(0), UserEdit::Longer(0), UserEdit::AtomicReplace(0)]
                .into_iter()
                .map(|edit| {
                    let mut s = base(2, Stage::Committed, Barrier::Survives);
                    s.flushed = vec![false, false];
                    s.cuts = vec![Cut::New, Cut::Partial];
                    s.user_edit = edit;
                    s
                })
                .collect()
        }),
        (Lane::A, other) => eager_empty(other),
        (Lane::J, _) => PowerCutCell::Empty("no power-cut driver for the hydrate lane yet"),
        (Lane::M, _) => PowerCutCell::Empty("no power-cut driver for the repair rebuild yet"),
        (Lane::EF, _) => PowerCutCell::Empty("symlink and directory (E/F) are not on the op yet"),
        (Lane::H, _) => PowerCutCell::Empty("no power-cut driver for the tombstone delete yet"),
    }
}

fn fault_cell(lane: Lane, point: WriteOpFailpoint) -> FaultCell {
    use WriteOpFailpoint::*;
    let test = |source, name| FaultCell::Test { source, name };
    match (lane, point) {
        (
            Lane::A,
            AfterPrepare | AfterStage | BeforePublish | AfterPublish | AfterObserve | BeforeProve,
        ) => test(
            EAGER_TESTS,
            "a_write_stopped_at_each_transition_before_the_proof_is_finished_by_the_retry",
        ),
        (Lane::A, AfterProve) => {
            test(EAGER_TESTS, "a_fault_after_the_proof_finds_the_write_closed")
        }
        (Lane::A, BeforeBarrier2) => {
            test(EAGER_TESTS, "a_fault_before_barrier_two_keeps_the_intent_for_startup_repair")
        }
        (Lane::A, AfterBarrier2) => {
            test(EAGER_TESTS, "a_fault_after_barrier_two_finds_the_write_closed")
        }
        (Lane::J, AfterPublish) => test(
            HYDRATION_TESTS,
            "a_failure_after_the_hydration_placed_its_bytes_leaves_the_intent_for_the_next_attempt",
        ),
        (Lane::J, AfterPrepare | BeforeProve | AfterProve) => test(
            HYDRATION_TESTS,
            "a_hydration_stopped_at_each_other_transition_is_completed_by_the_next_attempt",
        ),
        (Lane::H, BeforeProve) => test(
            DELETE_TESTS,
            "a_failure_after_the_removal_leaves_the_delete_intent_for_the_next_pass",
        ),
        (Lane::H, AfterPrepare | AfterPublish | AfterProve) => test(
            DELETE_TESTS,
            "a_delete_stopped_at_each_other_transition_is_settled_by_the_next_pass",
        ),
        // Single-object placement: the symlink tests, and the directory table test for the
        // same four hooks (`directory.rs`).
        (Lane::EF, AfterPublish) => {
            test(SYMLINK_TESTS, "a_failure_after_the_link_was_placed_leaves_its_intent_open")
        }
        (Lane::EF, AfterPrepare | BeforeProve | AfterProve) => test(
            SYMLINK_TESTS,
            "a_symlink_write_stopped_at_each_other_transition_is_completed_by_the_retry",
        ),
        // Repair rebuild: the four fs-sync points are `RepairFailpoint`, the proof commit is
        // the daemon's own.
        (Lane::M, AfterPrepare | AfterStage | BeforePublish | AfterPublish) => test(
            REPAIR_TESTS,
            "a_repair_reconstruct_stopped_at_each_transition_loses_nothing_and_leaves_no_temp",
        ),
        (Lane::M, BeforeProve) => test(
            REPAIR_TESTS,
            "a_repair_reconstruct_whose_proof_commit_fails_keeps_its_intent_open",
        ),
        (Lane::M, AfterProve) => {
            test(REPAIR_TESTS, "a_probe_after_a_repair_reconstructs_proof_finds_it_proven")
        }
        (Lane::J | Lane::H | Lane::EF | Lane::M, _) => FaultCell::Empty(NO_STAGE_OR_BARRIER),
    }
}

/// Every lane has a cell for every state and failpoint, filled or documented empty.
#[test]
fn every_lane_has_a_cell_for_every_state_and_failpoint() {
    let mut empty_without_reason = Vec::new();
    for lane in Lane::ALL {
        let states = lane.states();
        for state in states {
            if let PowerCutCell::Empty(reason) = power_cut_cell(lane, *state) {
                if reason.trim().len() < 15 {
                    empty_without_reason.push(format!("{lane:?} {state:?}"));
                }
            }
        }
        for point in WriteOpFailpoint::ALL {
            if let FaultCell::Empty(reason) = fault_cell(lane, point) {
                if reason.trim().len() < 15 {
                    empty_without_reason.push(format!("{lane:?} {point:?}"));
                }
            }
        }
    }
    assert!(empty_without_reason.is_empty(), "{empty_without_reason:?}");
}

/// Lane A, which runs on the operation, has no empty fault cell and fills the power-cut
/// states a cut can reach.
#[test]
fn the_eager_lane_fills_every_fault_cell_and_the_reachable_states() {
    assert!(WriteOpFailpoint::ALL
        .into_iter()
        .all(|point| matches!(fault_cell(Lane::A, point), FaultCell::Test { .. })));
    let filled: Vec<_> = Lane::A
        .states()
        .iter()
        .filter(|s| matches!(power_cut_cell(Lane::A, **s), PowerCutCell::Cut(_)))
        .collect();
    assert_eq!(filled.len(), 5, "{filled:?}");
}

/// A fault cell names a test that exists in the lane's own test module.
#[test]
fn every_filled_fault_cell_names_an_existing_test() {
    for lane in Lane::ALL {
        for point in WriteOpFailpoint::ALL {
            if let FaultCell::Test { source, name } = fault_cell(lane, point) {
                assert!(source.contains(&format!("fn {name}(")), "{lane:?} {point:?}: {name}");
            }
        }
    }
}

/// The directory placement of the single-object lane is covered at the same four hooks.
#[test]
fn the_single_object_lane_also_has_a_directory_fault_test() {
    assert!(DIRECTORY_TESTS.contains(
        "fn a_directory_write_stopped_at_each_transition_is_completed_by_the_next_pass("
    ));
}

/// The hooks the lanes that run on the operation implement are the ones the matrix fills: a
/// lane with a hook at a point must not leave the cell empty.
#[test]
fn the_migrated_lanes_fill_the_four_hooks_they_share() {
    use WriteOpFailpoint::*;
    for lane in [Lane::J, Lane::H, Lane::EF, Lane::M] {
        for point in [AfterPrepare, AfterPublish, BeforeProve, AfterProve] {
            assert!(
                matches!(fault_cell(lane, point), FaultCell::Test { .. }),
                "{lane:?} {point:?}"
            );
        }
    }
}

/// Runs every filled power-cut cell: each scenario cuts in the state the cell claims, and the
/// real receive, the cut and the real repair keep every invariant of the PowerCut driver.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_matrix_runs_every_filled_power_cut_cell() {
    for lane in Lane::ALL {
        for state in lane.states() {
            let PowerCutCell::Cut(scenarios) = power_cut_cell(lane, *state) else { continue };
            for scenario in scenarios() {
                assert_eq!(
                    scenario.crash_state(),
                    *state,
                    "{lane:?}: this scenario cuts in another state: {scenario:?}"
                );
                if let Err(violation) = run_scenario(&scenario).await {
                    panic!("{lane:?} {state:?}: {violation}\nscenario: {scenario:?}");
                }
            }
        }
    }
}

/// The kinds the matrix covers are the ones the fault matrix table names.
#[test]
fn the_lanes_cover_materialize_single_object_and_delete() {
    let kinds: Vec<_> = Lane::ALL.iter().map(|l| l.kind()).collect();
    for kind in [OpKind::Materialize, OpKind::SingleObject, OpKind::Delete] {
        assert!(kinds.contains(&kind), "{kind:?}");
    }
}
