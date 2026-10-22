//! The host's report of which items the operating system holds bytes of (the materialized set).
//!
//! The daemon cannot see the sync root, and it drops an item's cached blocks or asks the host to
//! drop the OS copy only for an item its evidence shows the OS holds with the current content:
//! a handoff the daemon made (its ledger), a materialized set the host reported, and the report
//! must have BEGUN after that handoff (`observed_after_seq`). This module is the host's half of
//! that protocol (`ProviderMaterializedReport`, see `shellipc.proto`): one [`Reporter`] per served
//! root and connection, an epoch of its own, a paged full snapshot first, then deltas.
//!
//! A reporter holds no truth of its own. The set it is given is read from the sync root at the
//! moment it is called; a report the daemon refuses (`needs_full`) or a connection that ends
//! starts a new reporter and so a new full snapshot.

use std::collections::HashSet;

use yadorilink_ipc_proto::shellipc::{ProviderMaterializedItem, ProviderMaterializedReport};

/// Items per page of a full snapshot (the frame limit is far above this).
const PAGE: usize = 2000;

pub struct Reporter {
    epoch: u64,
    seq: u64,
    observed_after: u64,
    reported: HashSet<Vec<u8>>,
}

impl Reporter {
    /// A reporter with its own epoch. Epochs must grow across restarts of the host, so the clock
    /// seeds it.
    pub fn new() -> Self {
        Self::after(0)
    }

    /// A reporter whose epoch is above `previous` and above the clock-seeded value of any
    /// earlier host process.
    pub fn after(previous: u64) -> Self {
        let clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
        Self::with_epoch(clock.max(previous.saturating_add(1)))
    }

    pub fn with_epoch(epoch: u64) -> Self {
        Self { epoch, seq: 0, observed_after: 0, reported: HashSet::new() }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// What to send now so the daemon knows `now` as the materialized set, read after evidence
    /// sequence `observed_after`. Nothing when nothing changed and no newer evidence was seen.
    pub fn reports(
        &mut self,
        root: &[u8],
        observed_after: u64,
        now: &HashSet<Vec<u8>>,
    ) -> Vec<ProviderMaterializedReport> {
        // Within an epoch the observation never goes back.
        let observed_after = observed_after.max(self.observed_after);
        // The daemon stamps an item with the evidence sequence of the report that LISTED it, and
        // only an upsert lists. Newer evidence therefore needs every member listed again, which
        // only a full snapshot does cheaply: it starts the next epoch.
        if self.seq > 0 && observed_after > self.observed_after {
            self.epoch += 1;
            self.seq = 0;
        }
        let epoch = self.epoch;
        let base = |seq, full| ProviderMaterializedReport {
            root_id: root.to_vec(),
            reporter_epoch: epoch,
            report_seq: seq,
            full,
            observed_after_seq: observed_after,
            ..Default::default()
        };
        if self.seq == 0 {
            let mut ids: Vec<&Vec<u8>> = now.iter().collect();
            ids.sort();
            let pages: Vec<&[&Vec<u8>]> =
                if ids.is_empty() { vec![&[]] } else { ids.chunks(PAGE).collect() };
            let last = pages.len() - 1;
            let reports = pages
                .iter()
                .enumerate()
                .map(|(n, page)| ProviderMaterializedReport {
                    upserts: page
                        .iter()
                        .map(|id| ProviderMaterializedItem { item_id: (*id).clone() })
                        .collect(),
                    more: n != last,
                    ..base(n as u64 + 1, true)
                })
                .collect::<Vec<_>>();
            self.seq = reports.len() as u64;
            self.observed_after = observed_after;
            self.reported = now.clone();
            return reports;
        }
        if *now == self.reported {
            return Vec::new();
        }
        let mut added: Vec<Vec<u8>> = now.difference(&self.reported).cloned().collect();
        let mut removed: Vec<Vec<u8>> = self.reported.difference(now).cloned().collect();
        added.sort();
        removed.sort();
        self.seq += 1;
        self.observed_after = observed_after;
        self.reported = now.clone();
        vec![ProviderMaterializedReport {
            upserts: added
                .into_iter()
                .map(|item_id| ProviderMaterializedItem { item_id })
                .collect(),
            removed,
            ..base(self.seq, false)
        }]
    }

    /// The daemon's answer. True when the report was refused as out of protocol: the caller
    /// replaces this reporter with a new one (a new epoch and a full snapshot).
    pub fn needs_restart(&self, epoch: u64, needs_full: bool) -> bool {
        needs_full && epoch == self.epoch
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[u8]) -> HashSet<Vec<u8>> {
        ids.iter().map(|id| vec![*id; 16]).collect()
    }

    #[test]
    fn the_first_report_is_a_full_snapshot_in_pages_and_a_later_one_is_a_delta() {
        let mut reporter = Reporter::with_epoch(7);
        let big: HashSet<Vec<u8>> =
            (0..(PAGE as u32 * 2 + 5)).map(|n| n.to_be_bytes().to_vec()).collect();
        let pages = reporter.reports(b"r", 3, &big);
        assert_eq!(pages.len(), 3);
        assert!(pages.iter().all(|p| p.full && p.reporter_epoch == 7 && p.observed_after_seq == 3));
        assert_eq!(pages.iter().map(|p| p.report_seq).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(pages.iter().map(|p| p.more).collect::<Vec<_>>(), [true, true, false]);
        assert_eq!(pages.iter().map(|p| p.upserts.len()).sum::<usize>(), big.len());

        let mut next = big.clone();
        next.remove(0u32.to_be_bytes().as_slice());
        next.insert(vec![9; 4]);
        let delta = reporter.reports(b"r", 3, &next);
        assert_eq!(delta.len(), 1);
        assert!(!delta[0].full && delta[0].report_seq == 4);
        assert_eq!(delta[0].upserts.len(), 1);
        assert_eq!(delta[0].removed, vec![0u32.to_be_bytes().to_vec()]);
    }

    #[test]
    fn an_empty_set_is_still_a_complete_snapshot() {
        let mut reporter = Reporter::with_epoch(1);
        let reports = reporter.reports(b"r", 0, &HashSet::new());
        assert_eq!(reports.len(), 1);
        assert!(reports[0].full && !reports[0].more && reports[0].upserts.is_empty());
    }

    /// Nothing is sent while nothing changed. Newer evidence lists every member again in the next
    /// epoch (the daemon stamps an item with the evidence of the report that listed it), and the
    /// observation never goes back.
    #[test]
    fn newer_evidence_lists_every_member_again_in_a_new_epoch() {
        let mut reporter = Reporter::with_epoch(10);
        reporter.reports(b"r", 5, &set(&[1, 2]));
        assert!(reporter.reports(b"r", 5, &set(&[1, 2])).is_empty());
        assert!(reporter.reports(b"r", 4, &set(&[1, 2])).is_empty());
        let fresher = reporter.reports(b"r", 6, &set(&[1, 2]));
        assert_eq!(fresher.len(), 1);
        assert!(fresher[0].full && fresher[0].report_seq == 1 && fresher[0].reporter_epoch == 11);
        assert_eq!((fresher[0].observed_after_seq, fresher[0].upserts.len()), (6, 2));
        let older = reporter.reports(b"r", 2, &set(&[1, 2, 3]));
        assert!(!older[0].full);
        assert_eq!(older[0].observed_after_seq, 6, "the observation went back");
    }

    #[test]
    fn a_new_reporter_is_above_the_epoch_it_follows() {
        assert!(Reporter::after(u64::MAX - 5).epoch() > u64::MAX - 5);
        assert!(Reporter::after(0).epoch() > 0);
    }

    #[test]
    fn only_a_refusal_of_this_epoch_restarts_the_reporter() {
        let reporter = Reporter::with_epoch(4);
        assert!(reporter.needs_restart(4, true));
        assert!(!reporter.needs_restart(3, true));
        assert!(!reporter.needs_restart(4, false));
    }
}
