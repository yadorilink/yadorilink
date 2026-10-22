//! The history floor: a redelivered delta below an author's floor that the log no
//! longer holds is history this replica cannot verify; the same missing entry
//! anywhere else is drift in the log and stays a malformed verdict.

use super::*;
use crate::native_checkpoint_frontier::{
    adopt_current_state_for_test, most_recently_adopted_checkpoint,
};
use crate::native_history_floor::{
    adopt_history_floor, floor_entry, history_floor, retained_frontier, verify_history_floor,
};

struct Chain {
    c: Connection,
    a: AuthorId,
    key: SigningKey,
    deltas: Vec<NativeDelta>,
}

impl Chain {
    fn lookup(&self) -> impl Fn(&AuthorId) -> Option<VerifyingKey> {
        keys(vec![(self.a.clone(), self.key.clone())])
    }

    fn admit(&self, delta: &NativeDelta) -> NativeAdmission {
        admit_native_delta(&self.c, &group(), delta, &self.lookup()).unwrap()
    }

    fn extend(&mut self, path: &str, version: u8) {
        let prev = self.deltas.last().map(|d| d.delta_hash());
        let seq = self.deltas.len() as u64 + 1;
        let path = format!("{path}{seq}");
        let d = delta(&self.a, seq, prev, &path, version, vec![], &self.key);
        let verdict = self.admit(&d);
        assert!(matches!(verdict, NativeAdmission::Admitted { .. }), "{verdict:?}");
        self.deltas.push(d);
    }

    fn forget(&self, seq: u64) {
        self.c.execute("DELETE FROM native_delta_log WHERE seq = ?1", [seq as i64]).unwrap();
    }

    fn floor_here(&self) -> [u8; 32] {
        let id = adopt_current_state_for_test(&self.c, &group()).unwrap();
        adopt_history_floor(&self.c, &group(), &id).unwrap();
        id
    }
}

fn chain(len: u64) -> Chain {
    let mut chain = Chain { c: conn(), a: author("a"), key: key(1), deltas: Vec::new() };
    for n in 1..=len {
        chain.extend("x", n as u8);
    }
    chain
}

#[test]
fn a_missing_entry_below_the_floor_is_prior_history_truncated() {
    let chain = chain(3);
    chain.floor_here();
    chain.forget(2);
    assert_eq!(
        chain.admit(&chain.deltas[1]),
        NativeAdmission::PriorHistoryTruncated { at_seq: AuthorSeq(2) }
    );
}

#[test]
fn an_entry_still_in_the_log_below_the_floor_is_a_duplicate() {
    let chain = chain(3);
    chain.floor_here();
    assert_eq!(chain.admit(&chain.deltas[0]), NativeAdmission::Duplicate);
}

#[test]
fn a_different_delta_still_in_the_log_below_the_floor_is_an_equivocation() {
    let chain = chain(3);
    chain.floor_here();
    let forked =
        delta(&chain.a, 2, Some(chain.deltas[0].delta_hash()), "x", 99, vec![], &chain.key);
    assert!(matches!(chain.admit(&forked), NativeAdmission::Equivocation(_)));
}

#[test]
fn a_missing_entry_above_the_floor_is_drift_not_truncation() {
    let mut chain = chain(1);
    chain.floor_here();
    chain.extend("y", 2);
    chain.extend("z", 3);
    chain.forget(2);
    let verdict = chain.admit(&chain.deltas[1]);
    assert!(matches!(verdict, NativeAdmission::Malformed(_)), "{verdict:?}");
}

#[test]
fn a_checkpoint_without_a_floor_does_not_hide_drift() {
    let chain = chain(2);
    // A sealed, trusted checkpoint exists, but no floor was adopted.
    adopt_current_state_for_test(&chain.c, &group()).unwrap();
    assert!(most_recently_adopted_checkpoint(&chain.c, &group()).unwrap().is_some());
    chain.forget(1);
    let verdict = chain.admit(&chain.deltas[0]);
    assert!(matches!(verdict, NativeAdmission::Malformed(_)), "{verdict:?}");
}

#[test]
fn an_author_the_floor_does_not_cover_is_drift() {
    let mut chain = chain(1);
    chain.floor_here();
    // A second author appears above the floor and loses a log entry.
    let b = author("b");
    let kb = key(2);
    let b1 = delta(&b, 1, None, "q", 5, vec![], &kb);
    let lookup = keys(vec![(b.clone(), kb.clone()), (chain.a.clone(), chain.key.clone())]);
    admit_native_delta(&chain.c, &group(), &b1, &lookup).unwrap();
    let b2 = delta(&b, 2, Some(b1.delta_hash()), "q", 6, vec![], &kb);
    admit_native_delta(&chain.c, &group(), &b2, &lookup).unwrap();
    chain.c.execute("DELETE FROM native_delta_log WHERE author = 'b' AND seq = 1", []).unwrap();
    let verdict = admit_native_delta(&chain.c, &group(), &b1, &lookup).unwrap();
    assert!(matches!(verdict, NativeAdmission::Malformed(_)), "{verdict:?}");
    chain.extend("w", 7);
}

#[test]
fn the_floor_tip_recognises_a_fork_at_the_floor_sequence() {
    let chain = chain(2);
    chain.floor_here();
    chain.forget(2);
    // The very delta the floor names: not a fork, not drift.
    assert_eq!(chain.admit(&chain.deltas[1]), NativeAdmission::Duplicate);
    // The same sequence and predecessor, a different body: a fork across the floor.
    let forked =
        delta(&chain.a, 2, Some(chain.deltas[0].delta_hash()), "x", 77, vec![], &chain.key);
    assert!(matches!(chain.admit(&forked), NativeAdmission::Equivocation(_)));
}

#[test]
fn a_delta_above_the_floor_is_classified_as_before() {
    let mut chain = chain(1);
    chain.floor_here();
    chain.extend("y", 2);
    assert_eq!(chain.admit(&chain.deltas[1]), NativeAdmission::Duplicate);
    let next = delta(&chain.a, 3, Some(chain.deltas[1].delta_hash()), "z", 3, vec![], &chain.key);
    assert!(matches!(chain.admit(&next), NativeAdmission::Admitted { .. }));
}

#[test]
fn the_marker_names_a_trusted_checkpoint_and_the_retained_frontier_is_its_frontier() {
    let chain = chain(2);
    assert!(history_floor(&chain.c, &group()).unwrap().is_none());
    assert!(retained_frontier(&chain.c, &group()).unwrap().is_empty());
    let id = chain.floor_here();
    let floor = history_floor(&chain.c, &group()).unwrap().unwrap();
    assert_eq!(floor.checkpoint_id, id);
    assert_eq!(
        retained_frontier(&chain.c, &group()).unwrap(),
        crate::native_store::load_frontier(&chain.c, &group()).unwrap()
    );
    assert_eq!(floor_entry(&chain.c, &group(), &chain.a).unwrap().unwrap().seq, AuthorSeq(2));
    assert!(floor_entry(&chain.c, &group(), &author("nobody")).unwrap().is_none());
    verify_history_floor(&chain.c, &group()).unwrap();
}

#[test]
fn a_checkpoint_that_is_not_trusted_cannot_be_the_floor() {
    let chain = chain(2);
    let key = SigningKey::from_bytes(&[13; 32]);
    let checkpoint = crate::native_store::seal_checkpoint(&chain.c, &group(), &key).unwrap();
    crate::native_store::install_checkpoint(&chain.c, &group(), &checkpoint, &key.verifying_key())
        .unwrap();
    let id = checkpoint.checkpoint_hash().0;
    adopt_history_floor(&chain.c, &group(), &id).unwrap_err();
    adopt_history_floor(&chain.c, &group(), &[9; 32]).unwrap_err();
    assert!(history_floor(&chain.c, &group()).unwrap().is_none());
}

#[test]
fn the_floor_never_moves_back_and_naming_it_again_changes_nothing() {
    let mut chain = chain(1);
    let older = chain.floor_here();
    chain.extend("y", 2);
    let newer = chain.floor_here();
    assert_ne!(older, newer);
    let before = history_floor(&chain.c, &group()).unwrap().unwrap();
    adopt_history_floor(&chain.c, &group(), &older).unwrap_err();
    adopt_history_floor(&chain.c, &group(), &newer).unwrap();
    assert_eq!(history_floor(&chain.c, &group()).unwrap().unwrap(), before);
}

#[test]
fn a_replica_that_does_not_descend_from_the_checkpoint_cannot_adopt_it_as_floor() {
    let chain = chain(2);
    let id = adopt_current_state_for_test(&chain.c, &group()).unwrap();
    // A replica holding the checkpoint's rows but a shorter state of its own.
    chain.c.execute("UPDATE native_author_frontier SET seq = 1", []).unwrap();
    adopt_history_floor(&chain.c, &group(), &id).unwrap_err();
    assert!(history_floor(&chain.c, &group()).unwrap().is_none());
}

#[test]
fn a_marker_whose_rows_no_longer_build_its_root_fails_verification() {
    let chain = chain(2);
    chain.floor_here();
    chain.c.execute("UPDATE native_checkpoint_frontier SET seq = seq + 1", []).unwrap();
    verify_history_floor(&chain.c, &group()).unwrap_err();
}

#[test]
fn eligible_floor_reads_only_trusted_checkpoints_and_changes_nothing() {
    use crate::native_history_floor::{eligible_floor, HistoryHorizon};
    let mut chain = chain(1);
    let first = adopt_current_state_for_test(&chain.c, &group()).unwrap();
    chain.extend("y", 2);
    let second = adopt_current_state_for_test(&chain.c, &group()).unwrap();
    chain.extend("z", 3);
    let third = adopt_current_state_for_test(&chain.c, &group()).unwrap();
    // A checkpoint installed without a verified seal is no candidate.
    chain.extend("w", 4);
    let key = SigningKey::from_bytes(&[13; 32]);
    let untrusted = crate::native_store::seal_checkpoint(&chain.c, &group(), &key).unwrap();
    crate::native_store::install_checkpoint(&chain.c, &group(), &untrusted, &key.verifying_key())
        .unwrap();
    let day = 86_400;
    let now = 1_000 * day;
    for (id, age_days) in [(first, 50), (second, 40), (third, 35)] {
        chain
            .c
            .execute(
                "UPDATE native_checkpoints SET installed_at_unixtime = ?1 \
                 WHERE checkpoint_hash = ?2",
                (now - age_days * day, id.as_slice()),
            )
            .unwrap();
    }
    let horizon = HistoryHorizon::default();
    assert_eq!(eligible_floor(&chain.c, &group(), now, &horizon).unwrap(), Some(first));
    assert!(history_floor(&chain.c, &group()).unwrap().is_none(), "it only answers");

    adopt_history_floor(&chain.c, &group(), &first).unwrap();
    assert_eq!(eligible_floor(&chain.c, &group(), now, &horizon).unwrap(), None);
    let one = HistoryHorizon { min_newer_generations: 1, ..horizon };
    assert_eq!(eligible_floor(&chain.c, &group(), now, &one).unwrap(), Some(second));
}
