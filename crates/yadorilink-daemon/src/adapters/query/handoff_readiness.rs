//! `DaemonState`-backed [`HandoffReadinessPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::daemon_state::DaemonState;
use crate::queries::handoff_readiness::{BoxFutureAlias, HandoffReadinessPort};

pub(crate) struct DaemonHandoffReadinessReader {
    state: Arc<DaemonState>,
}

impl DaemonHandoffReadinessReader {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl HandoffReadinessPort for DaemonHandoffReadinessReader {
    fn ready<'a>(&'a self, group_id: &'a str) -> BoxFutureAlias<'a, bool> {
        Box::pin(self.state.another_full_replica_is_ready(group_id))
    }

    fn not_ready_excluding<'a>(
        &'a self,
        group_id: &'a str,
        excluded_device_id: &'a str,
    ) -> BoxFutureAlias<'a, Result<Vec<String>, SyncError>> {
        Box::pin(async move {
            let candidate_groups: Vec<String> = if group_id.is_empty() {
                self.state
                    .replica_coordinator
                    .link_repository()
                    .list_links()?
                    .into_iter()
                    .map(|l| l.group_id)
                    .collect()
            } else {
                vec![group_id.to_string()]
            };
            let mut not_ready = Vec::new();
            for candidate in candidate_groups {
                if !self.state.authority.peer_group_is_full_replica(excluded_device_id, &candidate)
                {
                    continue;
                }
                if !self
                    .state
                    .another_full_replica_is_ready_excluding(&candidate, excluded_device_id)
                    .await
                {
                    not_ready.push(candidate);
                }
            }
            Ok(not_ready)
        })
    }
}
