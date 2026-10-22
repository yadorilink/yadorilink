//! What a replica has learned about peers that no longer hold the history it needs.
//!
//! A peer answers a request that starts below its retained history with a
//! history-truncated refusal that names its retained checkpoint. The requester
//! records it per peer and group. This is only a record, and a peer that merely
//! cannot serve a bootstrap is never in it: that is not a statement about its
//! history.
//!
//! Whether a replica should stop catching up by deltas is decided by
//! [`HistoryTruncations::should_leave_incremental`]. It is a pure predicate; nothing
//! here acts on it.

use std::collections::BTreeMap;

use crate::ids::FolderGroupId;

/// What a truncating peer said its retained history is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedSummary {
    /// The trusted checkpoint the peer's retained history begins at.
    pub checkpoint_id: [u8; 32],
    /// The frontier root that checkpoint's rows build.
    pub frontier_root: [u8; 32],
}

/// A state a replica could install in place of catching up by deltas, already
/// obtained and verified. Holding one is a precondition of leaving the incremental
/// path; naming what it would install is what makes it checkable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCandidate {
    pub checkpoint_id: [u8; 32],
}

/// The refusals recorded so far, per peer and group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryTruncations {
    /// `None`: the peer no longer holds a delta this replica needs but named no checkpoint
    /// its retained history begins at (its own log was collected).
    by_peer: BTreeMap<String, BTreeMap<FolderGroupId, Option<RetainedSummary>>>,
}

impl HistoryTruncations {
    /// Records that `peer` refused a request for `group` because it starts below the
    /// history `summary` describes. A later refusal replaces an earlier one.
    pub fn record(&mut self, peer: &str, group: &FolderGroupId, summary: RetainedSummary) {
        self.by_peer.entry(peer.to_owned()).or_default().insert(group.clone(), Some(summary));
    }

    /// Records that `peer` no longer holds a delta this replica needs, without a checkpoint its
    /// retained history begins at: it collected its own log. Counts like a truncation for
    /// [`Self::should_leave_incremental`], but is not reported by [`Self::truncated_by`], which
    /// names checkpoints. A named record is not replaced by this one.
    pub fn record_uncovered(&mut self, peer: &str, group: &FolderGroupId) {
        self.by_peer.entry(peer.to_owned()).or_default().entry(group.clone()).or_insert(None);
    }

    /// Forgets that `peer` truncated `group`: it answered a round without refusing.
    pub fn clear(&mut self, peer: &str, group: &FolderGroupId) {
        if let Some(groups) = self.by_peer.get_mut(peer) {
            groups.remove(group);
            if groups.is_empty() {
                self.by_peer.remove(peer);
            }
        }
    }

    /// Forgets everything recorded about `peer`: its connection ended, and what it
    /// retains may differ when it returns.
    pub fn forget_peer(&mut self, peer: &str) {
        self.by_peer.remove(peer);
    }

    /// What `peer` has said it retains, per group.
    pub fn truncated_by(&self, peer: &str) -> BTreeMap<FolderGroupId, RetainedSummary> {
        self.by_peer
            .get(peer)
            .map(|groups| {
                groups
                    .iter()
                    .filter_map(|(group, summary)| summary.map(|s| (group.clone(), s)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether `peer` is recorded as having truncated `group`.
    pub fn is_truncated(&self, peer: &str, group: &FolderGroupId) -> bool {
        self.by_peer.get(peer).is_some_and(|groups| groups.contains_key(group))
    }

    /// Whether `group` should stop catching up by deltas: every peer in
    /// `connected` has truncated it, and a verified installable candidate is
    /// already in hand. An empty `connected` is never true, a peer that is
    /// connected but has said nothing about its history (one that merely could
    /// not serve a bootstrap, say) counts as not truncated, and a recorded peer
    /// that is no longer connected does not count.
    pub fn should_leave_incremental(
        &self,
        group: &FolderGroupId,
        connected: &[&str],
        candidate: Option<&VerifiedCandidate>,
    ) -> bool {
        candidate.is_some()
            && !connected.is_empty()
            && connected.iter().all(|peer| self.is_truncated(peer, group))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> FolderGroupId {
        FolderGroupId(name.into())
    }

    fn summary(seed: u8) -> RetainedSummary {
        RetainedSummary { checkpoint_id: [seed; 32], frontier_root: [seed + 1; 32] }
    }

    const CANDIDATE: VerifiedCandidate = VerifiedCandidate { checkpoint_id: [9; 32] };

    #[test]
    fn a_refusal_is_recorded_per_peer_and_group() {
        let mut truncations = HistoryTruncations::default();
        truncations.record("p1", &group("g"), summary(1));
        truncations.record("p1", &group("h"), summary(2));
        truncations.record("p2", &group("g"), summary(3));
        assert_eq!(truncations.truncated_by("p1").len(), 2);
        assert_eq!(truncations.truncated_by("p1")[&group("g")], summary(1));
        assert_eq!(truncations.truncated_by("p2")[&group("g")], summary(3));
        assert!(truncations.truncated_by("nobody").is_empty());
        assert!(truncations.is_truncated("p1", &group("h")));
        assert!(!truncations.is_truncated("p2", &group("h")));
    }

    #[test]
    fn a_later_refusal_replaces_an_earlier_one_and_a_clear_forgets_it() {
        let mut truncations = HistoryTruncations::default();
        truncations.record("p", &group("g"), summary(1));
        truncations.record("p", &group("g"), summary(5));
        assert_eq!(truncations.truncated_by("p")[&group("g")], summary(5));
        truncations.clear("p", &group("g"));
        assert!(!truncations.is_truncated("p", &group("g")));
        assert_eq!(truncations, HistoryTruncations::default());
    }

    #[test]
    fn forgetting_a_peer_forgets_all_its_groups() {
        let mut truncations = HistoryTruncations::default();
        truncations.record("p", &group("g"), summary(1));
        truncations.record("p", &group("h"), summary(1));
        truncations.record("q", &group("g"), summary(1));
        truncations.forget_peer("p");
        assert!(truncations.truncated_by("p").is_empty());
        assert!(truncations.is_truncated("q", &group("g")));
    }

    #[test]
    fn leaving_incremental_needs_every_connected_peer_truncated_and_a_candidate() {
        let g = group("g");
        let mut truncations = HistoryTruncations::default();
        truncations.record("p1", &g, summary(1));
        truncations.record("p2", &g, summary(1));
        assert!(truncations.should_leave_incremental(&g, &["p1", "p2"], Some(&CANDIDATE)));
        assert!(truncations.should_leave_incremental(&g, &["p1"], Some(&CANDIDATE)));
    }

    #[test]
    fn no_peers_is_never_true() {
        let truncations = HistoryTruncations::default();
        assert!(!truncations.should_leave_incremental(&group("g"), &[], Some(&CANDIDATE)));
    }

    #[test]
    fn a_candidate_is_required() {
        let g = group("g");
        let mut truncations = HistoryTruncations::default();
        truncations.record("p1", &g, summary(1));
        assert!(!truncations.should_leave_incremental(&g, &["p1"], None));
    }

    #[test]
    fn one_connected_peer_that_has_not_truncated_blocks_it() {
        let g = group("g");
        let mut truncations = HistoryTruncations::default();
        truncations.record("p1", &g, summary(1));
        // p2 is connected but only could not serve a bootstrap: nothing recorded.
        assert!(!truncations.should_leave_incremental(&g, &["p1", "p2"], Some(&CANDIDATE)));
    }

    #[test]
    fn a_recorded_peer_that_is_gone_does_not_count_and_the_group_matters() {
        let g = group("g");
        let mut truncations = HistoryTruncations::default();
        truncations.record("gone", &g, summary(1));
        truncations.record("here", &group("other"), summary(1));
        assert!(!truncations.should_leave_incremental(&g, &["here"], Some(&CANDIDATE)));
        assert!(!truncations.should_leave_incremental(&g, &["here", "gone"], Some(&CANDIDATE)));
    }

    #[test]
    fn a_peer_that_collected_its_own_log_counts_as_truncated_but_names_no_checkpoint() {
        let mut truncations = HistoryTruncations::default();
        let g = group("g");
        truncations.record_uncovered("p1", &g);
        assert!(truncations.is_truncated("p1", &g));
        assert!(truncations.truncated_by("p1").is_empty());
        assert!(truncations.should_leave_incremental(&g, &["p1"], Some(&CANDIDATE)));
        // A named record is kept when the same peer is later recorded without one.
        truncations.record("p2", &g, summary(1));
        truncations.record_uncovered("p2", &g);
        assert_eq!(truncations.truncated_by("p2").len(), 1);
    }
}
