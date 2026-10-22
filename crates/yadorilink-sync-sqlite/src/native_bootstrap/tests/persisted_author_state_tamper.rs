//! The author states a checkpoint commits (open or closed, the cutoff, and the
//! difference between a cutoff and none) are bound to the signed root end to end:
//! altering only one stored value of an adopted checkpoint's persisted rows is
//! caught by root recomputation, by naming the checkpoint as the history floor, by
//! the floor's integrity check and by adopting the stored rows again.

use super::*;
use crate::native_checkpoint_frontier::{
    adopt_verified_checkpoint, checkpoint_coverage, CheckpointCoverage,
};
use crate::native_history_floor::{adopt_history_floor, verify_history_floor};
use yadorilink_replica_domain::native_frontier::AuthorState;

/// A replica that joined a bundle, with the checkpoint id and the bundle whose
/// checkpoint carries the signed root.
struct Adopted {
    target: Connection,
    id: [u8; 32],
    bundle: NativeBootstrap,
}

fn adopted(close: &dyn Fn(&Connection, &AuthorId, &AuthorId)) -> Adopted {
    let (source, a, b) = source();
    close(&source, &a, &b);
    let bundle = built(&source);
    let target = conn();
    join_bundle(bundle.clone(), &target).unwrap();
    let id = bundle.checkpoint.checkpoint_hash().0;
    Adopted { target, id, bundle }
}

/// `device-b` is closed at its frontier entry; `device-a` stays open.
fn closed_b() -> Adopted {
    adopted(&|c, _a, b| {
        close_author(c, &group(), b);
    })
}

/// `device-d` closed before its first delta: the author the frontier lacks.
fn closed_before_first_delta() -> Adopted {
    adopted(&|c, _a, _b| {
        close_author(c, &group(), &author("device-d"));
    })
}

impl Adopted {
    fn tamper(&self, sql: &str) {
        let changed = self.target.execute(sql, [self.id.as_slice()]).unwrap();
        assert!(changed > 0, "the tamper changed no row: {sql}");
    }

    /// What each defence says about the persisted rows now.
    fn verdicts(&self) -> [(&'static str, bool); 4] {
        let coverage = checkpoint_coverage(&self.target, &group(), &self.id).unwrap();
        let root_matches =
            coverage.check_against_root(&self.bundle.checkpoint.author_state_root.0).is_ok();
        let readopt = adopt_verified_checkpoint(
            &self.target,
            &group(),
            &self.bundle.checkpoint,
            &self.bundle.seal.clone().unwrap(),
            &sealer_key().verifying_key(),
            &CheckpointCoverage { states: coverage.states.clone() },
        );
        [
            ("root recomputation", root_matches),
            ("naming it the floor", adopt_history_floor(&self.target, &group(), &self.id).is_ok()),
            ("the floor's integrity check", verify_history_floor(&self.target, &group()).is_ok()),
            ("adopting the stored rows again", readopt.is_ok()),
        ]
    }

    fn assert_every_defence_fires(&self, what: &str) {
        for (defence, passes) in self.verdicts() {
            assert!(!passes, "{what}: {defence} accepted the altered rows");
        }
    }
}

const OF_B: &str = "WHERE checkpoint_id = ?1 AND author = 'device-b'";
const OF_D: &str = "WHERE checkpoint_id = ?1 AND author = 'device-d'";

#[test]
fn the_untouched_rows_pass_every_defence() {
    for adopted in [closed_b(), closed_before_first_delta()] {
        for (defence, passes) in adopted.verdicts() {
            assert!(passes, "{defence} refused the genuine rows");
        }
    }
}

#[test]
fn only_the_stored_open_or_closed_flag_altered_is_caught_either_way() {
    let closed = closed_b();
    assert!(matches!(
        checkpoint_coverage(&closed.target, &group(), &closed.id).unwrap().states
            [&author("device-b")],
        AuthorState::Closed { .. }
    ));
    closed.tamper(&format!("UPDATE native_checkpoint_frontier SET closed = 0 {OF_B}"));
    closed.assert_every_defence_fires("a closed author stored as open");

    let open = closed_b();
    open.tamper("UPDATE native_checkpoint_frontier SET closed = 1 WHERE checkpoint_id = ?1 AND author = 'device-a'");
    open.assert_every_defence_fires("an open author stored as closed");
}

#[test]
fn only_the_stored_cutoff_altered_is_caught() {
    for column in ["seq = seq + 1", "tip = zeroblob(32)"] {
        let adopted = closed_b();
        adopted.tamper(&format!("UPDATE native_checkpoint_frontier SET {column} {OF_B}"));
        adopted.assert_every_defence_fires(column);
    }
}

#[test]
fn a_stored_cutoff_turned_into_none_and_none_into_a_cutoff_are_caught() {
    let some_to_none = closed_b();
    some_to_none.tamper(&format!(
        "UPDATE native_checkpoint_frontier \
         SET seq = NULL, tip = NULL {OF_B}"
    ));
    some_to_none.assert_every_defence_fires("Some turned into None");

    let none_to_some = closed_before_first_delta();
    none_to_some.tamper(&format!(
        "UPDATE native_checkpoint_frontier \
         SET seq = 1, tip = zeroblob(32) {OF_D}"
    ));
    none_to_some.assert_every_defence_fires("None turned into Some");
}

#[test]
fn a_closed_authors_row_removed_from_the_stored_states_is_caught() {
    let adopted = closed_b();
    adopted.tamper(&format!("DELETE FROM native_checkpoint_frontier {OF_B}"));
    adopted.assert_every_defence_fires("the closed author's row removed");
}

/// An author closed before its first delta is committed as an explicit closed
/// state with no entry; the stored rows hold no sequence-0 row to stand in for
/// the absence, and an open author cannot be stored without an entry.
#[test]
fn an_author_without_an_entry_is_an_explicit_closed_state_and_never_a_sequence_zero_row() {
    let adopted = closed_before_first_delta();
    let never_seen = author("device-d");
    let coverage = checkpoint_coverage(&adopted.target, &group(), &adopted.id).unwrap();
    assert!(!coverage.frontier().contains_key(&never_seen), "no entry is invented for it");
    assert_eq!(
        coverage.states[&never_seen],
        AuthorState::Closed { frontier: None },
        "the absence is the state's explicit None"
    );

    let seq_zero = adopted.target.execute(
        "INSERT INTO native_checkpoint_frontier \
         (group_id, checkpoint_id, author, incarnation, closed, seq, tip) \
         VALUES ('boot', ?1, 'device-e', zeroblob(16), 1, 0, zeroblob(32))",
        [adopted.id.as_slice()],
    );
    assert!(seq_zero.is_err(), "a sequence-0 row was storable");

    let open_without_an_entry = adopted.target.execute(
        &format!("UPDATE native_checkpoint_frontier SET closed = 0 {OF_D}"),
        [adopted.id.as_slice()],
    );
    assert!(open_without_an_entry.is_err(), "an open author without an entry was storable");
}
