//! `DaemonState`-backed [`ReplicaReadinessPort`].

use std::sync::Arc;

use crate::application::ports::{BoxFuture, ReplicaReadinessPort};
use crate::daemon_state::{DaemonState, GroupPolicyResolution};

pub(crate) struct DaemonReplicaReadinessAdapter {
    state: Arc<DaemonState>,
}

impl DaemonReplicaReadinessAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl ReplicaReadinessPort for DaemonReplicaReadinessAdapter {
    fn another_full_replica_is_ready_excluding<'a>(
        &'a self,
        group_id: &'a str,
        excluded_device_id: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            self.state.another_full_replica_is_ready_excluding(group_id, excluded_device_id).await
        })
    }

    fn verified_policy_shows_non_member<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            match self.state.resolve_group_policy(group_id) {
                GroupPolicyResolution::Verified(policy) => {
                    !policy.current_members().iter().any(|member| member.device_id == device_id)
                }
                GroupPolicyResolution::Withhold | GroupPolicyResolution::Bootstrap => false,
            }
        })
    }

    fn groups_shared_with_peer<'a>(&'a self, device_id: &'a str) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let mut groups = self.state.authority.authorized_groups_for_peer(device_id);
            for group_id in self.state.authority.full_replica_groups_for_peer(device_id) {
                if !groups.contains(&group_id) {
                    groups.push(group_id);
                }
            }
            groups
        })
    }

    fn peer_eager_replica_groups<'a>(
        &'a self,
        device_id: &'a str,
        candidate_group_ids: &'a [String],
    ) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let netmap_groups = self.state.authority.full_replica_groups_for_peer(device_id);
            let mut evidence: Vec<String> = candidate_group_ids
                .iter()
                .filter(|group_id| netmap_groups.contains(group_id))
                .cloned()
                .collect();
            let Some(session) = self.state.peers.session(device_id) else {
                return evidence;
            };
            let unanswered: Vec<&String> = candidate_group_ids
                .iter()
                .filter(|group_id| !evidence.contains(group_id))
                .collect();
            let answers = futures_util::future::join_all(unanswered.into_iter().map(|group_id| {
                let session = session.clone();
                async move {
                    let summary = tokio::time::timeout(
                        DIRECT_SUMMARY_TIMEOUT,
                        session.request_group_durability_summary(group_id),
                    )
                    .await
                    .ok()
                    .flatten();
                    (group_id, summary)
                }
            }))
            .await;
            for (group_id, summary) in answers {
                if summary.is_some_and(|summary| summary.eager) {
                    evidence.push(group_id.clone());
                }
            }
            evidence
        })
    }
}

/// How long a removal waits for a peer's direct answer. The answer can only
/// widen the at-risk set, so a slow or silent peer is simply not evidence.
const DIRECT_SUMMARY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
