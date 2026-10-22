//! `DaemonState`-backed [`HandoffReadinessPort`] -- full-replica readiness
//! confirmation and lease acquisition both go over an established
//! peer-to-peer session, never the coordination plane's own HTTP API.

use std::sync::Arc;

use crate::application::ports::{BoxFuture, HandoffReadinessPort};
use crate::daemon_state::DaemonState;
use crate::handoff_proof::StrongHandoffProof;

pub(crate) struct DaemonHandoffReadinessAdapter {
    state: Arc<DaemonState>,
}

impl DaemonHandoffReadinessAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl HandoffReadinessPort for DaemonHandoffReadinessAdapter {
    fn is_local_full_replica(&self, group_id: &str) -> bool {
        self.state.is_local_full_replica(group_id)
    }

    fn full_replica_handoff_proof<'a>(
        &'a self,
        group_id: &'a str,
    ) -> BoxFuture<'a, Option<StrongHandoffProof>> {
        Box::pin(async move { self.state.full_replica_handoff_proof(group_id).await })
    }

    fn obtain_handoff_lease_from_peer<'a>(
        &'a self,
        group_id: &'a str,
        target_peer_device_id: &'a str,
        my_digest: [u8; 32],
    ) -> BoxFuture<'a, Option<String>> {
        Box::pin(async move {
            self.state
                .obtain_handoff_lease_from_peer(group_id, target_peer_device_id, my_digest)
                .await
        })
    }
}
