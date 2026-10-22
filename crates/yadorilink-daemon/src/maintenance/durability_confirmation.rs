//! `DurabilityConfirmationJob` -- the periodic sweep that keeps
//! `DaemonState::group_durability_status`'s `Protected` standing on real
//! peer evidence rather than on this device's own opinion of itself.
//!
//! It used to do that by re-running the action-time handoff proof for every
//! linked group: one `VersionPresent(for_handoff = true)` round-trip per
//! durability root, each of which made the peer read that version's blocks
//! back off its own disk and re-hash them. Eight thousand roots meant eight
//! thousand of each, every ninety seconds, to refresh a status indicator.
//!
//! It now runs `background_custody::run_cycle`, which asks each candidate
//! peer one question about the whole group and reads no block on either
//! side. What that answer means -- and, more importantly, what it does not
//! -- is `BackgroundCustodyEvidence`'s own doc comment; the short version is
//! that it is a health signal and never a permission, and that every
//! destructive action still establishes the strong form for itself at the
//! moment it acts.
//!
//! Structurally still mirrors `MaterializationRepairJob` -- same shape (a
//! struct holding its components, a `sweep_interval()` accessor read
//! fresh each sleep, an `async fn run_once`), same reason: the
//! correctness-bearing part lives elsewhere and is independently tested;
//! this job owns only *when* it runs. Unlike that job it does not hold
//! `DaemonState`: it holds exactly what a cycle reads (see
//! `background_custody::CustodyCycleComponents`) plus the coordinator whose
//! link table and file index it walks.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::background_custody::{run_cycle, CustodyCycleComponents};
use crate::daemon_state::PeerAuthorityState;
use crate::durability_service::DurabilityService;
use crate::peer_connectivity_runtime::PeerConnectivityRuntime;
use crate::peer_registry::PeerRegistry;
use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) struct DurabilityConfirmationJob {
    durability: Arc<DurabilityService>,
    authority: Arc<PeerAuthorityState>,
    peers: Arc<PeerRegistry>,
    peer_connectivity: Arc<PeerConnectivityRuntime>,
    replica_coordinator: Arc<ReplicaCoordinator>,
}

impl DurabilityConfirmationJob {
    pub(crate) fn new(
        durability: Arc<DurabilityService>,
        authority: Arc<PeerAuthorityState>,
        peers: Arc<PeerRegistry>,
        peer_connectivity: Arc<PeerConnectivityRuntime>,
        replica_coordinator: Arc<ReplicaCoordinator>,
    ) -> Self {
        Self { durability, authority, peers, peer_connectivity, replica_coordinator }
    }

    pub(crate) fn sweep_interval(&self) -> Duration {
        self.durability.custody_confirmation_sweep_interval()
    }

    /// Runs one background custody cycle for every non-orphaned linked
    /// group.
    ///
    /// Every round writes a record either way. A negative round never
    /// itself produces `Protected` -- only a fresh positive does -- but it
    /// DOES mark the group as having been swept at least once, which is what
    /// lets `classify` distinguish "checked, found nothing" (eligible for
    /// the structural `AtRisk` conclusion) from "never checked yet" (must
    /// stay `Unknown` however the structural peer check would otherwise
    /// read).
    ///
    /// Groups are still walked in sequence, and that is now unremarkable: a
    /// cycle is one concurrent fan-out under one timeout, so a group waits
    /// on at most one timeout window per group ahead of it and on nothing
    /// that scales with how much any of them holds.
    pub(crate) async fn run_once(&self) {
        let groups: HashSet<String> = match self.replica_coordinator.link_repository().list_links()
        {
            Ok(links) => {
                links.into_iter().filter(|link| !link.orphaned).map(|link| link.group_id).collect()
            }
            Err(e) => {
                tracing::warn!(error = %e, "durability confirmation sweep failed to list links");
                return;
            }
        };
        let components = CustodyCycleComponents {
            durability: &self.durability,
            authority: &self.authority,
            peers: &self.peers,
            peer_connectivity: &self.peer_connectivity,
            file_index: self.replica_coordinator.file_index_repository(),
        };
        for group_id in groups {
            // The outcome is the caller's business only when someone asked
            // for a specific cycle; the periodic sweep publishes whatever it
            // finds and moves on. Same cycle `DaemonState::
            // refresh_custody_confirmation` runs.
            let _ = run_cycle(&components, &group_id).await;
        }
    }
}
