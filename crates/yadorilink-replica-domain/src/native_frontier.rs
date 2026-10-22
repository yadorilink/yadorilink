//! `NativeAuthorFrontier`: authenticated sync/equivocation metadata for the
//! native causal state — kept as its own first-class domain type, **not**
//! folded into [`crate::native_state::NativeState`].
//!
//! Product decision (2026-09-28): a tip header hash is signed-delta-chain /
//! equivocation-detection / sync-frontier metadata, not semantic head
//! state. `NativeState.context` stays exactly `AuthorId -> AuthorSeq` — the
//! minimal causal-semantics state — and never grows a tip field.
//! `NativeAuthorFrontier` is the separate, authenticated record of each
//! author's chain position **and** the header hash of the delta that
//! attained it.
//!
//! **Invariant callers must maintain, never this module alone:**
//! `state.context[author] == frontier[author].seq` for every author present
//! in either, checked at every transaction boundary that installs both
//! together (`yadorilink-sync-sqlite::native_store::install_verified_delta`).
//! A tip is only ever advanced by a *verified* `NativeDelta` or a *verified*
//! `NativeCheckpoint` — never guessed, never a placeholder — so this module
//! exposes no way to construct a `NativeAuthorFrontierEntry` other than by
//! naming its fields directly from already-verified material.

use std::collections::BTreeMap;

use crate::author::AuthorId;
use crate::ids::AuthorSeq;
use crate::native_protocol::native_domain_tag;
use crate::native_state::DeltaHash;

/// One author's position in the frontier: the sequence it has reached, and
/// the header hash of the delta that reached it (`None` only transiently in
/// memory before a first delta; a persisted entry always has a real tip —
/// see `NativeAuthorFrontier`'s doc on how a fresh author's first entry is
/// created).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NativeAuthorFrontierEntry {
    pub seq: AuthorSeq,
    pub tip: DeltaHash,
}

/// Per-author frontier entries for one group. An absent author has never
/// advanced the frontier here.
pub type NativeAuthorFrontier = BTreeMap<AuthorId, NativeAuthorFrontierEntry>;

/// One author-incarnation's state: it is open at its frontier entry, or closed.
/// A closed author's `frontier` is its cutoff: deltas above its sequence are
/// inadmissible. `None` closes the author before its first delta (no sequence is
/// admissible, and no entry exists or is invented: an entry always names a real
/// sequence and tip).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthorState {
    Open(NativeAuthorFrontierEntry),
    Closed { frontier: Option<NativeAuthorFrontierEntry> },
}

impl AuthorState {
    /// The author's position, if it has one.
    pub fn entry(&self) -> Option<&NativeAuthorFrontierEntry> {
        match self {
            Self::Open(entry) => Some(entry),
            Self::Closed { frontier } => frontier.as_ref(),
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }
}

/// Every author of a group with its state: the one map a checkpoint commits to.
pub type NativeAuthorStates = BTreeMap<AuthorId, AuthorState>;

/// The positions the states hold: every author that has an entry, closed ones
/// included.
pub fn frontier_of_states(states: &NativeAuthorStates) -> NativeAuthorFrontier {
    states
        .iter()
        .filter_map(|(author, state)| state.entry().map(|entry| (author.clone(), *entry)))
        .collect()
}

/// Domain tag of the author-state root.
pub const AUTHOR_STATE_ROOT_TAG: &[u8; 8] = &native_domain_tag(b"YLNKasr");

/// Whether a delta at `seq` lies beyond a closure's cutoff: `None` closes the
/// author before its first delta, so every sequence is beyond it; `Some(cutoff)`
/// admits sequences up to and including `cutoff` (a replica that is behind still
/// needs them) and nothing above.
pub fn beyond_closed_cutoff(cutoff: Option<AuthorSeq>, seq: AuthorSeq) -> bool {
    cutoff.is_none_or(|cutoff| seq > cutoff)
}

/// The author-state root a checkpoint signs: a hash over every author in author
/// order, committing for each whether it is open or closed and its entry or the
/// absence of one. Changing any of them changes the root, so a carried state
/// cannot differ from the signed one in openness or cutoff, and "no entry" cannot
/// pass for an entry or the reverse.
pub fn author_state_root(states: &NativeAuthorStates) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut buf = Vec::new();
    buf.extend_from_slice(AUTHOR_STATE_ROOT_TAG);
    buf.extend_from_slice(&(states.len() as u64).to_be_bytes());
    for (author, state) in states {
        author.encode_into(&mut buf);
        let (kind, entry) = match state {
            AuthorState::Open(entry) => (0u8, Some(entry)),
            AuthorState::Closed { frontier: Some(entry) } => (1, Some(entry)),
            AuthorState::Closed { frontier: None } => (2, None),
        };
        buf.push(kind);
        if let Some(entry) = entry {
            buf.extend_from_slice(&entry.seq.get().to_be_bytes());
            buf.extend_from_slice(&entry.tip.0);
        }
    }
    Sha256::digest(&buf).into()
}

/// Two frontier entries claim the same sequence for one author with
/// different tips — equivocation, never resolved by picking a side. Mirrors
/// `native_state::Fork`'s fail-closed shape for the semantic-state case.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrontierFork {
    pub author: AuthorId,
    pub seq: AuthorSeq,
    pub left_tip: DeltaHash,
    pub right_tip: DeltaHash,
}

/// Joins two frontiers: per author, the higher-seq entry wins; equal seq
/// must carry identical tips (spec-adjacent decision: "same seq / same tip
/// = identical, same seq / different tip = equivocation").
pub fn join(
    left: &NativeAuthorFrontier,
    right: &NativeAuthorFrontier,
) -> Result<NativeAuthorFrontier, FrontierFork> {
    let mut out = left.clone();
    for (author, right_entry) in right {
        match out.get(author) {
            None => {
                out.insert(author.clone(), *right_entry);
            }
            Some(left_entry) => {
                if left_entry.seq == right_entry.seq {
                    if left_entry.tip != right_entry.tip {
                        return Err(FrontierFork {
                            author: author.clone(),
                            seq: left_entry.seq,
                            left_tip: left_entry.tip,
                            right_tip: right_entry.tip,
                        });
                    }
                } else if right_entry.seq > left_entry.seq {
                    out.insert(author.clone(), *right_entry);
                }
            }
        }
    }
    Ok(out)
}

/// Whether `later` dominates `earlier` under this frontier's natural
/// partial order: every author `earlier` has a position for is present in
/// `later`, at either a strictly higher seq, or the SAME seq with an
/// IDENTICAL tip. An author present in `earlier` but absent from `later`,
/// present in both at a lower seq in `later`, or present in both at the
/// same seq with a DIFFERENT tip, all mean `later` does not dominate.
///
/// The equal-seq-different-tip case is deliberately not treated as
/// domination in either direction: that shape is [`FrontierFork`]
/// equivocation (a fact [`join`] surfaces separately, as an error, when it
/// is asked to merge two such frontiers) -- two entries that disagree
/// about what happened at one seq are not one extending the other, so
/// neither may be said to dominate the other on the strength of that seq
/// alone. This helper only answers the ordering question, not the fork
/// question, so callers doing nondominated-checkpoint retention
/// get a total, decidable comparison over two frontiers that are each
/// individually valid: a fork-shaped disagreement simply falls out as
/// "neither dominates," the same outcome as any other incomparable pair,
/// and both sides are retained.
///
/// Comparing entries that did not both come from THIS replica's own,
/// single, monotonically-advancing frontier history (the only shape
/// [`crate::native_checkpoint::NativeCheckpoint`] corroboration currently
/// ever compares) is outside what a bare `(seq, tip)` snapshot can prove:
/// a strictly higher seq is trusted here to mean a legitimate causal
/// continuation, which this function cannot itself verify without the
/// intervening delta chain -- see `native_checkpoint_authorization`'s own
/// doc for the corroboration discipline that keeps this sound in practice
/// today, and the open question it flags for a future chain-of-custody
/// check across independently-sealed checkpoints.
///
/// Two frontiers with neither dominating the other are concurrent
/// (checkpoints from two sealers, or the same sealer's tip observed
/// mid-partition-and-heal) and must both be retained.
pub fn dominates(later: &NativeAuthorFrontier, earlier: &NativeAuthorFrontier) -> bool {
    earlier.iter().all(|(author, earlier_entry)| {
        later.get(author).is_some_and(|later_entry| {
            if later_entry.seq == earlier_entry.seq {
                later_entry.tip == earlier_entry.tip
            } else {
                later_entry.seq > earlier_entry.seq
            }
        })
    })
}

/// Why a claimed `(prev, seq)` does not continue an author's frontier
/// chain — fail closed; the caller must refuse the delta, never guess
/// which side is right.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ChainAdvanceError {
    #[error("a fresh author's first delta must carry seq {expected:?}, found {found:?}")]
    WrongFirstSeq { expected: AuthorSeq, found: AuthorSeq },
    #[error("expected the next seq after {current:?} ({expected:?}), found {found:?}")]
    WrongNextSeq { current: AuthorSeq, expected: AuthorSeq, found: AuthorSeq },
    #[error(
        "author has reached the highest storable sequence ({current:?}); no next delta is possible"
    )]
    SeqExhausted { current: AuthorSeq },
    #[error("expected prev to name the current tip ({expected:?}), found {found:?}")]
    ChainBreak { expected: Option<DeltaHash>, found: Option<DeltaHash> },
}

/// Whether a delta claiming `(claimed_prev, claimed_seq)` legitimately
/// continues `current`'s chain (`None` for a fresh author with no frontier
/// entry yet). This is the "higher seq requires correct previous tip
/// chain" rule: a claimed seq must be exactly the next one after `current`,
/// and `claimed_prev` must name `current`'s own tip exactly (`None` only
/// for a fresh author's first delta).
pub fn check_chain_advance(
    current: Option<&NativeAuthorFrontierEntry>,
    claimed_prev: Option<DeltaHash>,
    claimed_seq: AuthorSeq,
) -> Result<(), ChainAdvanceError> {
    match current {
        None => {
            if claimed_seq != AuthorSeq::FIRST {
                return Err(ChainAdvanceError::WrongFirstSeq {
                    expected: AuthorSeq::FIRST,
                    found: claimed_seq,
                });
            }
            if claimed_prev.is_some() {
                return Err(ChainAdvanceError::ChainBreak { expected: None, found: claimed_prev });
            }
            Ok(())
        }
        Some(entry) => {
            let expected = entry
                .seq
                .checked_next()
                .ok_or(ChainAdvanceError::SeqExhausted { current: entry.seq })?;
            if claimed_seq != expected {
                return Err(ChainAdvanceError::WrongNextSeq {
                    current: entry.seq,
                    expected,
                    found: claimed_seq,
                });
            }
            if claimed_prev != Some(entry.tip) {
                return Err(ChainAdvanceError::ChainBreak {
                    expected: Some(entry.tip),
                    found: claimed_prev,
                });
            }
            Ok(())
        }
    }
}

/// What a receiver must do next with a delta claiming `(claimed_prev,
/// claimed_seq)`, derived from [`check_chain_advance`]'s verdict alone (remote
/// admission). Two of the four failure shapes are decidable from
/// the frontier's current entry alone; the other two need the receiver's
/// own historical log of past seqs (this module keeps only the *current*
/// tip per author, not the full chain, so it cannot tell a byte-identical
/// replay from a genuine fork on its own — see [`ChainGate::NeedsHistoryLookup`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainGate {
    /// Continues cleanly. The op-level context gate (a separate, per-op
    /// concern — see `native_state::receive_verified`'s doc) still applies
    /// before the delta may be installed.
    Continues,
    /// Exactly the next seq this author's chain expects, but naming the
    /// wrong predecessor tip (or, for a fresh author, naming any
    /// predecessor at all): two different deltas at the one legitimate
    /// next position. A definite fork, decidable without any history
    /// lookup.
    Equivocation {
        at_seq: AuthorSeq,
        expected_prev: Option<DeltaHash>,
        found_prev: Option<DeltaHash>,
    },
    /// Ahead of this author's known chain: hold until the delta naming
    /// `missing_through` (and everything the receiver still lacks below
    /// it) arrives.
    NeedsPredecessor { missing_through: AuthorSeq },
    /// At or behind this author's already-recorded position, but not
    /// exactly equal to the exhausted `current` head of an existing
    /// legitimate-next check (i.e. not [`ChainGate::Equivocation`]'s
    /// case): a re-delivery of a past seq. The receiver's own persisted
    /// history at `at_seq` (not this module, which only ever keeps the
    /// current tip) decides duplicate (hash matches) from equivocation
    /// (hash differs).
    NeedsHistoryLookup { at_seq: AuthorSeq },
    /// The author has reached the highest storable sequence; no next
    /// delta from it is possible.
    SeqExhausted,
}

/// Classifies one [`check_chain_advance`] verdict into what the receiver
/// must do next. Pure and total: every [`ChainAdvanceError`] variant
/// maps to exactly one [`ChainGate`] case.
pub fn classify_chain_advance(
    current: Option<&NativeAuthorFrontierEntry>,
    claimed_prev: Option<DeltaHash>,
    claimed_seq: AuthorSeq,
) -> ChainGate {
    match check_chain_advance(current, claimed_prev, claimed_seq) {
        Ok(()) => ChainGate::Continues,
        Err(ChainAdvanceError::SeqExhausted { .. }) => ChainGate::SeqExhausted,
        Err(ChainAdvanceError::WrongFirstSeq { found, .. }) => {
            ChainGate::NeedsPredecessor { missing_through: found }
        }
        Err(ChainAdvanceError::ChainBreak { expected, found }) => ChainGate::Equivocation {
            at_seq: claimed_seq,
            expected_prev: expected,
            found_prev: found,
        },
        Err(ChainAdvanceError::WrongNextSeq { expected, found, .. }) => {
            if found > expected {
                ChainGate::NeedsPredecessor { missing_through: found }
            } else {
                ChainGate::NeedsHistoryLookup { at_seq: found }
            }
        }
    }
}

/// What a redelivered delta at or below its author's frontier is, when this
/// replica's log holds no entry at that sequence: decided from the author's
/// position in the history floor alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnloggedHistory {
    /// The delta is the floor's own tip.
    Duplicate,
    /// The sequence is the floor's, and the floor's tip is a different delta.
    Equivocation { known: DeltaHash },
    /// Below the floor: the entry was legitimately dropped and this replica cannot
    /// say what it was.
    PriorHistoryTruncated,
    /// Not at or below the floor (there is none, the floor holds no position for
    /// the author, or the sequence is above it): the log has lost an entry it
    /// must hold.
    Drift,
}

/// Classifies a delta (`delta_hash`, at `at_seq`) the log has no entry for, given
/// the author's `floor` entry. Pure and total.
pub fn classify_unlogged_history(
    floor: Option<&NativeAuthorFrontierEntry>,
    at_seq: AuthorSeq,
    delta_hash: DeltaHash,
) -> UnloggedHistory {
    let Some(floor) = floor else { return UnloggedHistory::Drift };
    match at_seq.cmp(&floor.seq) {
        std::cmp::Ordering::Less => UnloggedHistory::PriorHistoryTruncated,
        std::cmp::Ordering::Equal if floor.tip == delta_hash => UnloggedHistory::Duplicate,
        std::cmp::Ordering::Equal => UnloggedHistory::Equivocation { known: floor.tip },
        std::cmp::Ordering::Greater => UnloggedHistory::Drift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::author::IncarnationId;
    use crate::ids::DeviceId;

    fn author(name: &str) -> AuthorId {
        AuthorId { device: DeviceId(name.to_owned()), incarnation: IncarnationId([1u8; 16]) }
    }

    fn entry(seq: u64, tip: u8) -> NativeAuthorFrontierEntry {
        NativeAuthorFrontierEntry { seq: AuthorSeq(seq), tip: DeltaHash([tip; 32]) }
    }

    #[test]
    fn an_unlogged_delta_is_classified_by_the_authors_floor_entry() {
        let floor = entry(5, 9);
        let known = DeltaHash([9; 32]);
        let other = DeltaHash([8; 32]);
        let verdict = |floor: Option<&NativeAuthorFrontierEntry>, seq: u64, hash: DeltaHash| {
            classify_unlogged_history(floor, AuthorSeq(seq), hash)
        };
        assert_eq!(verdict(Some(&floor), 4, other), UnloggedHistory::PriorHistoryTruncated);
        assert_eq!(verdict(Some(&floor), 1, known), UnloggedHistory::PriorHistoryTruncated);
        assert_eq!(verdict(Some(&floor), 5, known), UnloggedHistory::Duplicate);
        assert_eq!(verdict(Some(&floor), 5, other), UnloggedHistory::Equivocation { known });
        assert_eq!(verdict(Some(&floor), 6, known), UnloggedHistory::Drift);
        assert_eq!(verdict(None, 1, known), UnloggedHistory::Drift);
    }

    #[test]
    fn same_seq_same_tip_joins_as_identical() {
        let mut left = NativeAuthorFrontier::new();
        left.insert(author("a"), entry(1, 9));
        let mut right = NativeAuthorFrontier::new();
        right.insert(author("a"), entry(1, 9));
        let joined = join(&left, &right).unwrap();
        assert_eq!(joined, left);
    }

    #[test]
    fn same_seq_different_tip_is_equivocation() {
        let mut left = NativeAuthorFrontier::new();
        left.insert(author("a"), entry(1, 9));
        let mut right = NativeAuthorFrontier::new();
        right.insert(author("a"), entry(1, 200));
        let err = join(&left, &right).unwrap_err();
        assert_eq!(err.author, author("a"));
        assert_eq!(err.seq, AuthorSeq(1));
    }

    #[test]
    fn higher_seq_wins_without_needing_the_chain_checked_here() {
        // `join` merges two already-legitimate frontiers (e.g. from two
        // synced replicas); chain continuity is `check_chain_advance`'s
        // job, exercised separately below, not `join`'s.
        let mut left = NativeAuthorFrontier::new();
        left.insert(author("a"), entry(1, 9));
        let mut right = NativeAuthorFrontier::new();
        right.insert(author("a"), entry(2, 200));
        let joined = join(&left, &right).unwrap();
        assert_eq!(joined[&author("a")], entry(2, 200));
    }

    #[test]
    fn fresh_author_must_start_at_seq_1_with_no_prev() {
        check_chain_advance(None, None, AuthorSeq::FIRST).unwrap();
        assert!(matches!(
            check_chain_advance(None, None, AuthorSeq(2)),
            Err(ChainAdvanceError::WrongFirstSeq { .. })
        ));
        assert!(matches!(
            check_chain_advance(None, Some(DeltaHash([1u8; 32])), AuthorSeq::FIRST),
            Err(ChainAdvanceError::ChainBreak { .. })
        ));
    }

    #[test]
    fn existing_author_must_advance_by_exactly_one_naming_the_current_tip() {
        let current = entry(3, 7);
        check_chain_advance(Some(&current), Some(DeltaHash([7u8; 32])), AuthorSeq(4)).unwrap();

        assert!(matches!(
            check_chain_advance(Some(&current), Some(DeltaHash([7u8; 32])), AuthorSeq(5)),
            Err(ChainAdvanceError::WrongNextSeq { .. })
        ));
        assert!(matches!(
            check_chain_advance(Some(&current), Some(DeltaHash([99u8; 32])), AuthorSeq(4)),
            Err(ChainAdvanceError::ChainBreak { .. })
        ));
        assert!(matches!(
            check_chain_advance(Some(&current), None, AuthorSeq(4)),
            Err(ChainAdvanceError::ChainBreak { .. })
        ));
    }

    // --- dominates -----------------------------------------------

    #[test]
    fn equal_frontiers_dominate_each_other() {
        let mut f = NativeAuthorFrontier::new();
        f.insert(author("a"), entry(2, 5));
        assert!(dominates(&f, &f));
    }

    #[test]
    fn a_strict_superset_at_equal_or_higher_seq_dominates() {
        let mut earlier = NativeAuthorFrontier::new();
        earlier.insert(author("a"), entry(1, 1));
        let mut later = NativeAuthorFrontier::new();
        later.insert(author("a"), entry(2, 2));
        later.insert(author("b"), entry(1, 1));
        assert!(dominates(&later, &earlier));
        assert!(!dominates(&earlier, &later));
    }

    #[test]
    fn missing_or_behind_author_prevents_domination() {
        let mut earlier = NativeAuthorFrontier::new();
        earlier.insert(author("a"), entry(1, 1));
        earlier.insert(author("b"), entry(1, 1));
        let mut later = NativeAuthorFrontier::new();
        later.insert(author("a"), entry(2, 2)); // b missing entirely
        assert!(!dominates(&later, &earlier));

        let mut later_behind = NativeAuthorFrontier::new();
        later_behind.insert(author("a"), entry(1, 1));
        later_behind.insert(author("b"), entry(0, 0)); // seq 0 never real, but exercises the comparison
        assert!(!dominates(&later_behind, &earlier));
    }

    #[test]
    fn equal_seq_with_different_tips_dominates_neither_way() {
        // A fork-shaped disagreement: two checkpoints (or two sealers)
        // each claim seq 5 for the same author, but with different tips.
        // Neither may be said to dominate the other on the strength of
        // that seq alone -- both must be retained, exactly as any other
        // incomparable pair.
        let mut left = NativeAuthorFrontier::new();
        left.insert(author("a"), entry(5, 1));
        let mut right = NativeAuthorFrontier::new();
        right.insert(author("a"), entry(5, 2));
        assert!(!dominates(&left, &right));
        assert!(!dominates(&right, &left));
    }

    #[test]
    fn concurrent_progress_on_different_authors_is_incomparable() {
        let mut left = NativeAuthorFrontier::new();
        left.insert(author("a"), entry(2, 2));
        left.insert(author("b"), entry(1, 1));
        let mut right = NativeAuthorFrontier::new();
        right.insert(author("a"), entry(1, 1));
        right.insert(author("b"), entry(2, 2));
        assert!(!dominates(&left, &right));
        assert!(!dominates(&right, &left));
    }

    // --- classify_chain_advance --------------------------------

    #[test]
    fn classify_continues_on_a_legitimate_next_delta() {
        let current = entry(3, 7);
        assert_eq!(
            classify_chain_advance(Some(&current), Some(DeltaHash([7u8; 32])), AuthorSeq(4)),
            ChainGate::Continues
        );
        assert_eq!(classify_chain_advance(None, None, AuthorSeq::FIRST), ChainGate::Continues);
    }

    #[test]
    fn classify_holds_a_delta_ahead_of_the_known_chain() {
        let current = entry(3, 7);
        assert_eq!(
            classify_chain_advance(Some(&current), Some(DeltaHash([7u8; 32])), AuthorSeq(6)),
            ChainGate::NeedsPredecessor { missing_through: AuthorSeq(6) }
        );
        // A fresh author's delta claiming any seq beyond FIRST is likewise
        // ahead of a chain this replica has not started tracking yet.
        assert_eq!(
            classify_chain_advance(None, None, AuthorSeq(3)),
            ChainGate::NeedsPredecessor { missing_through: AuthorSeq(3) }
        );
    }

    #[test]
    fn classify_flags_definite_equivocation_at_the_legitimate_next_seq() {
        let current = entry(3, 7);
        assert_eq!(
            classify_chain_advance(Some(&current), Some(DeltaHash([99u8; 32])), AuthorSeq(4)),
            ChainGate::Equivocation {
                at_seq: AuthorSeq(4),
                expected_prev: Some(DeltaHash([7u8; 32])),
                found_prev: Some(DeltaHash([99u8; 32]))
            }
        );
        // A fresh author's first delta naming a nonexistent predecessor is
        // the same shape: the legitimate next position exists (FIRST, no
        // predecessor), and this delta names a different one.
        assert_eq!(
            classify_chain_advance(None, Some(DeltaHash([1u8; 32])), AuthorSeq::FIRST),
            ChainGate::Equivocation {
                at_seq: AuthorSeq::FIRST,
                expected_prev: None,
                found_prev: Some(DeltaHash([1u8; 32]))
            }
        );
    }

    #[test]
    fn classify_needs_history_for_a_seq_at_or_behind_the_known_chain() {
        let current = entry(3, 7);
        // Exactly the current seq, replayed (whether byte-identical or a
        // fork cannot be told without the receiver's own past-seq log).
        assert_eq!(
            classify_chain_advance(Some(&current), Some(DeltaHash([7u8; 32])), AuthorSeq(3)),
            ChainGate::NeedsHistoryLookup { at_seq: AuthorSeq(3) }
        );
        // Older than the current seq.
        assert_eq!(
            classify_chain_advance(Some(&current), None, AuthorSeq(1)),
            ChainGate::NeedsHistoryLookup { at_seq: AuthorSeq(1) }
        );
    }

    #[test]
    fn classify_reports_seq_exhausted() {
        let current = entry(AuthorSeq::MAX.get(), 7);
        assert_eq!(
            classify_chain_advance(
                Some(&current),
                Some(DeltaHash([7u8; 32])),
                AuthorSeq(AuthorSeq::MAX.get())
            ),
            ChainGate::SeqExhausted
        );
    }

    fn closed(name: &str, frontier: Option<NativeAuthorFrontierEntry>) -> (AuthorId, AuthorState) {
        (author(name), AuthorState::Closed { frontier })
    }

    fn states(list: &[(AuthorId, AuthorState)]) -> NativeAuthorStates {
        list.iter().cloned().collect()
    }

    #[test]
    fn the_cutoff_is_inclusive_and_none_closes_every_sequence() {
        let cutoff = Some(AuthorSeq(3));
        assert!(!beyond_closed_cutoff(cutoff, AuthorSeq(3)));
        assert!(beyond_closed_cutoff(cutoff, AuthorSeq(4)));
        assert!(!beyond_closed_cutoff(cutoff, AuthorSeq(1)));
        assert!(beyond_closed_cutoff(None, AuthorSeq(1)));
    }

    #[test]
    fn author_state_root_commits_open_and_closed_and_none_vs_some() {
        let base = states(&[closed("a", Some(entry(3, 9)))]);
        let root = author_state_root(&base);
        let variants = [
            states(&[(author("a"), AuthorState::Open(entry(3, 9)))]),
            states(&[closed("a", Some(entry(4, 9)))]),
            states(&[closed("a", Some(entry(3, 8)))]),
            states(&[closed("a", None)]),
            states(&[closed("b", Some(entry(3, 9)))]),
            states(&[closed("a", Some(entry(3, 9))), closed("b", None)]),
        ];
        for variant in &variants {
            assert_ne!(author_state_root(variant), root, "{variant:?}");
        }
        assert_ne!(author_state_root(&NativeAuthorStates::new()), root);
        // The three kinds of a lone author are three different commitments.
        let open = states(&[(author("a"), AuthorState::Open(entry(3, 9)))]);
        let none = states(&[closed("a", None)]);
        assert_ne!(author_state_root(&open), author_state_root(&none));
    }

    #[test]
    fn the_author_state_root_does_not_depend_on_insertion_order() {
        let forward = states(&[closed("a", None), (author("b"), AuthorState::Open(entry(1, 7)))]);
        let mut reversed = NativeAuthorStates::new();
        reversed.insert(author("b"), AuthorState::Open(entry(1, 7)));
        reversed.insert(author("a"), AuthorState::Closed { frontier: None });
        assert_eq!(author_state_root(&forward), author_state_root(&reversed));
    }

    /// The root of fixed states, byte for byte, under the current generation tag:
    /// changing the encoding without a new generation fails this.
    #[test]
    fn the_author_state_root_of_fixed_states_is_pinned_to_its_generation() {
        assert_eq!(&AUTHOR_STATE_ROOT_TAG[..7], b"YLNKasr");
        assert_eq!(AUTHOR_STATE_ROOT_TAG[7], crate::native_protocol::NATIVE_PROTOCOL_GENERATION);
        let fixed = states(&[
            closed("a", Some(entry(3, 9))),
            closed("b", None),
            (author("c"), AuthorState::Open(entry(1, 7))),
        ]);
        assert_eq!(
            hex::encode(author_state_root(&fixed)),
            "0950d4644c25416aa1e7bbbda95e006af0aca4880f8ce906bf1c67e799601dc0"
        );
    }

    #[test]
    fn the_frontier_of_states_holds_every_author_that_has_an_entry() {
        let fixed = states(&[
            closed("a", Some(entry(3, 9))),
            closed("b", None),
            (author("c"), AuthorState::Open(entry(1, 7))),
        ]);
        let frontier = frontier_of_states(&fixed);
        assert_eq!(frontier.len(), 2);
        assert_eq!(frontier[&author("a")], entry(3, 9));
        assert_eq!(frontier[&author("c")], entry(1, 7));
        assert!(fixed[&author("b")].is_closed());
        assert!(fixed[&author("b")].entry().is_none());
    }
}
