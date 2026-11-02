//! The ledger reads behind a group's durability and availability classification, behind one
//! trait so the classification is written once.
//!
//! [`LiveDb`] reads on demand, exactly as the classification always has; the decision paths
//! (unlink and handoff gates, the replacement confirmation) keep using it. [`CollectedDb`] holds
//! the same values read earlier by the status builder, so a status request classifies without
//! touching SQLite (`status_facts`).

use std::collections::HashSet;

use yadorilink_replica_domain::session_state::RootSetSummary;
use yadorilink_sync_sqlite::MaterializationCounts;

use crate::daemon_state::DaemonState;

/// A repair candidate of a local full replica and who has refused its current version: what the
/// "known unobtainable required content" test reads per path.
#[derive(Clone)]
pub(crate) struct UnobtainableCandidate {
    pub origin_device_id: String,
    pub refusers: HashSet<String>,
}

pub(crate) trait GroupDbSource {
    /// `None`: the counts could not be read (the classification fails closed on it).
    fn counts(&self) -> Option<MaterializationCounts>;
    /// A recovery-blocked membership operation exists; an unreadable table counts as one.
    fn recovery_blocked(&self) -> bool;
    fn is_local_full_replica(&self) -> bool;
    fn root_set_summary(&self) -> Option<RootSetSummary>;
    /// The digest of every durability root; read only when a strong proof is cached.
    fn roots_digest(&self) -> Option<[u8; 32]>;
    /// Empty unless the device is a local full replica with repair candidates. Lazy: the test
    /// that reads it stops at the first path that qualifies, and a gate must not pay for the rest.
    fn unobtainable_candidates(&self) -> Box<dyn Iterator<Item = UnobtainableCandidate> + '_>;
}

pub(crate) struct LiveDb<'a> {
    state: &'a DaemonState,
    group_id: &'a str,
}

impl<'a> LiveDb<'a> {
    pub(crate) fn new(state: &'a DaemonState, group_id: &'a str) -> Self {
        Self { state, group_id }
    }
}

impl GroupDbSource for LiveDb<'_> {
    fn counts(&self) -> Option<MaterializationCounts> {
        self.state
            .replica_coordinator
            .materialization_state_repository()
            .materialization_counts(self.group_id)
            .ok()
    }

    fn recovery_blocked(&self) -> bool {
        self.state
            .replica_coordinator
            .membership_operation_repository()
            .has_recovery_blocked_membership_operation()
            .unwrap_or(true)
    }

    fn is_local_full_replica(&self) -> bool {
        self.state.is_local_full_replica(self.group_id)
    }

    fn root_set_summary(&self) -> Option<RootSetSummary> {
        self.state.local_root_set_summary(self.group_id)
    }

    fn roots_digest(&self) -> Option<[u8; 32]> {
        self.state.local_durability_roots_digest(self.group_id)
    }

    fn unobtainable_candidates(&self) -> Box<dyn Iterator<Item = UnobtainableCandidate> + '_> {
        if !self.is_local_full_replica() {
            return Box::new(std::iter::empty());
        }
        let Ok(paths) = self
            .state
            .replica_coordinator
            .materialization_state_repository()
            .list_materialization_repair_candidates(self.group_id)
        else {
            return Box::new(std::iter::empty());
        };
        Box::new(paths.into_iter().filter_map(move |path| {
            // ONE read for the origin and the version alike. Refusal evidence is keyed by the
            // exact version it is about; a key stitched together out of separate reads can name a
            // version no incarnation of the row ever had and would match nothing, which is the
            // fail-open direction for "this content is unobtainable".
            let Ok(Some(row)) = self
                .state
                .replica_coordinator
                .file_index_repository()
                .canonical_current_row(self.group_id, &path)
            else {
                return None;
            };
            let origin_device_id = row.origin_device_id.clone()?;
            let current_version_hash = row.version_hash().to_hex();
            let Ok(refusers) = self
                .state
                .replica_coordinator
                .materialization_state_repository()
                .refusing_peers_for_path(self.group_id, &path, &current_version_hash)
            else {
                return None;
            };
            Some(UnobtainableCandidate { origin_device_id, refusers })
        }))
    }
}

/// Values read once, earlier, by the status builder.
#[derive(Clone)]
pub(crate) struct CollectedDb {
    pub counts: Option<MaterializationCounts>,
    pub recovery_blocked: bool,
    pub is_local_full_replica: bool,
    pub root_set_summary: Option<RootSetSummary>,
    /// `Some` only if a strong proof was cached when the group was collected; without it the
    /// evidence falls back to the index-corroborated level, never up.
    pub roots_digest: Option<[u8; 32]>,
    pub unobtainable_candidates: Vec<UnobtainableCandidate>,
}

impl CollectedDb {
    /// `counts` are the ones the caller has just read (and failed on, if they failed).
    pub(crate) fn collect_with_counts(
        state: &DaemonState,
        group_id: &str,
        counts: MaterializationCounts,
    ) -> Self {
        let live = LiveDb::new(state, group_id);
        let is_local_full_replica = live.is_local_full_replica();
        Self {
            counts: Some(counts),
            recovery_blocked: live.recovery_blocked(),
            is_local_full_replica,
            root_set_summary: live.root_set_summary(),
            roots_digest: state
                .durability_has_strong_proof(group_id)
                .then(|| live.roots_digest())
                .flatten(),
            unobtainable_candidates: live.unobtainable_candidates().collect(),
        }
    }
}

impl GroupDbSource for CollectedDb {
    fn counts(&self) -> Option<MaterializationCounts> {
        self.counts
    }
    fn recovery_blocked(&self) -> bool {
        self.recovery_blocked
    }
    fn is_local_full_replica(&self) -> bool {
        self.is_local_full_replica
    }
    fn root_set_summary(&self) -> Option<RootSetSummary> {
        self.root_set_summary
    }
    fn roots_digest(&self) -> Option<[u8; 32]> {
        self.roots_digest
    }
    fn unobtainable_candidates(&self) -> Box<dyn Iterator<Item = UnobtainableCandidate> + '_> {
        Box::new(self.unobtainable_candidates.iter().cloned())
    }
}
