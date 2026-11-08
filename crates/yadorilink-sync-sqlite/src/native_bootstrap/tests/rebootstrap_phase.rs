//! The journal moves only along the listed edges, and only from where it is.

use crate::native_rebootstrap::{
    advance, rebootstrap_status, set_journal_for_test, set_preserved, Phase,
};

use super::rebootstrap_preserve::private_tempdir;
use super::*;

const RID: &str = "recovery-under-test";

/// Written out here, apart from the table in the code, so that widening the table is a
/// test failure.
const EDGES: [(Phase, Phase); 5] = [
    (Phase::Planning, Phase::Capturing),
    (Phase::Capturing, Phase::Preserving),
    (Phase::Preserved, Phase::Quarantining),
    (Phase::Quarantining, Phase::CatchingUp),
    (Phase::CatchingUp, Phase::Replaying),
];

fn stored_state(c: &Connection) -> String {
    c.query_row("SELECT state FROM native_rebootstrap_journal", [], |r| r.get(0)).unwrap()
}

#[test]
fn only_listed_edges_advance_and_a_refusal_changes_nothing() {
    for from in Phase::ALL {
        for to in Phase::ALL {
            let c = conn();
            set_journal_for_test(&c, &group(), from.as_str(), RID);
            let result = advance(&c, &group(), RID, from, to, 7);
            if EDGES.contains(&(from, to)) {
                result.unwrap();
                assert_eq!(stored_state(&c), to.as_str());
            } else {
                assert!(result.is_err(), "{from:?} to {to:?} must be refused");
                assert_eq!(stored_state(&c), from.as_str());
            }
        }
    }
}

#[test]
fn an_edge_is_refused_from_another_state_or_another_rebootstrap() {
    let c = conn();
    set_journal_for_test(&c, &group(), "quarantining", RID);
    assert!(advance(&c, &group(), RID, Phase::Planning, Phase::Capturing, 7).is_err());
    assert!(advance(&c, &group(), "other", Phase::Quarantining, Phase::CatchingUp, 7).is_err());
    assert_eq!(stored_state(&c), "quarantining");
    advance(&c, &group(), RID, Phase::Quarantining, Phase::CatchingUp, 7).unwrap();
    assert_eq!(rebootstrap_status(&c, &group()).unwrap().unwrap().updated_at, 7);
}

#[test]
fn every_phase_reads_back_as_its_state() {
    for phase in Phase::ALL {
        let c = conn();
        set_journal_for_test(&c, &group(), phase.as_str(), RID);
        let status = rebootstrap_status(&c, &group()).unwrap().unwrap();
        assert_eq!(
            format!("{:?}", status.state).to_lowercase().replace('_', ""),
            phase.as_str().replace('_', "")
        );
    }
}

#[test]
fn the_barrier_is_written_only_from_preserving_under_its_own_id() {
    for from in Phase::ALL {
        let c = conn();
        set_journal_for_test(&c, &group(), from.as_str(), RID);
        let result = set_preserved(&c, &group(), RID, &[7u8; 32], 9);
        if from == Phase::Preserving {
            result.unwrap();
            let status = rebootstrap_status(&c, &group()).unwrap().unwrap();
            assert_eq!(status.manifest_sha256, Some([7u8; 32]));
            assert_eq!(stored_state(&c), "preserved");
        } else {
            assert!(result.is_err(), "the barrier must be refused from {from:?}");
            assert_eq!(stored_state(&c), from.as_str());
        }
    }
    let c = conn();
    set_journal_for_test(&c, &group(), "preserving", RID);
    assert!(set_preserved(&c, &group(), "other", &[7u8; 32], 9).is_err());
    assert_eq!(stored_state(&c), "preserving");
}

#[test]
fn the_state_predicates_name_exactly_their_phases() {
    for phase in Phase::ALL {
        let c = conn();
        set_journal_for_test(&c, &group(), phase.as_str(), RID);
        let state = rebootstrap_status(&c, &group()).unwrap().unwrap().state;
        let modified = matches!(phase, Phase::Quarantining | Phase::CatchingUp | Phase::Replaying);
        let barrier = modified || phase == Phase::Preserved;
        assert_eq!(state.root_modified(), modified, "{phase:?}");
        assert_eq!(state.has_barrier(), barrier, "{phase:?}");
        assert_eq!(state.is_installed(), matches!(phase, Phase::CatchingUp | Phase::Replaying));
    }
}

#[test]
fn the_rebootstrap_ends_only_from_replaying_under_its_own_id() {
    use crate::native_rebootstrap::finish_rebootstrap;
    for from in Phase::ALL {
        for id in [RID, "other"] {
            let c = conn();
            set_journal_for_test(&c, &group(), from.as_str(), RID);
            let finished = finish_rebootstrap(&c, &group(), id).unwrap();
            let rows: i64 = c
                .query_row("SELECT COUNT(*) FROM native_rebootstrap_journal", [], |r| r.get(0))
                .unwrap();
            if from == Phase::Replaying && id == RID {
                assert!(finished);
                assert_eq!(rows, 0);
            } else {
                assert!(!finished, "{from:?} under {id} must not end the rebootstrap");
                assert_eq!(rows, 1);
                assert_eq!(stored_state(&c), from.as_str());
            }
        }
    }
}

#[test]
fn a_journal_that_cannot_be_read_is_not_finished() {
    let c = conn();
    set_journal_for_test(&c, &group(), "replaying", RID);
    c.execute("UPDATE native_rebootstrap_journal SET blocked_reason = 'no such reason'", [])
        .unwrap();
    assert!(crate::native_rebootstrap::finish_rebootstrap(&c, &group(), RID).is_err());
    assert_eq!(stored_state(&c), "replaying");
}

#[test]
fn every_state_is_continued_by_the_one_table() {
    use crate::native_rebootstrap::{RebootstrapState as S, Resume as R};
    // Written out here, apart from the table in the code.
    let expected = [
        (Phase::Planning, R::BeforeBarrier),
        (Phase::Capturing, R::BeforeBarrier),
        (Phase::Preserving, R::BeforeBarrier),
        (Phase::Preserved, R::Install),
        (Phase::Quarantining, R::Install),
        (Phase::CatchingUp, R::CatchUp),
        (Phase::Replaying, R::Replay),
    ];
    assert_eq!(expected.len(), Phase::ALL.len(), "a phase is missing from this list");
    for (phase, resume) in expected {
        assert_eq!(phase.resume(), resume, "{phase:?}");
        let c = conn();
        set_journal_for_test(&c, &group(), phase.as_str(), RID);
        let state = rebootstrap_status(&c, &group()).unwrap().unwrap().state;
        assert_eq!(state.resume(), resume, "{phase:?} read back");
    }
    let blocked = S::Blocked(crate::native_rebootstrap::BlockedReason::DurabilityUnsupported);
    assert_eq!(blocked.resume(), R::Blocked);
}

/// A restart acts on what the table says: a journal before its barrier is discarded, any other
/// is verified against its area and, with no area, is blocked rather than dropped.
#[test]
fn a_restart_follows_the_table_for_every_phase() {
    use crate::native_rebootstrap::{recover_after_restart, RestartOutcome as O, Resume};
    for phase in Phase::ALL {
        let c = conn();
        set_journal_for_test(&c, &group(), phase.as_str(), "0123456789abcdef0123456789abcdef");
        let root = private_tempdir();
        let outcome = recover_after_restart(&c, root.path(), &group()).unwrap();
        match phase.resume() {
            Resume::BeforeBarrier => {
                assert!(matches!(outcome, O::Abandoned { .. }), "{phase:?}: {outcome:?}");
                assert_eq!(rebootstrap_status(&c, &group()).unwrap(), None);
            }
            _ => {
                assert!(matches!(outcome, O::Blocked(_)), "{phase:?}: {outcome:?}");
                assert!(rebootstrap_status(&c, &group()).unwrap().is_some());
            }
        }
    }
}
