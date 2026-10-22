//! `DaemonState`-backed [`DurabilityCommandPort`]/[`HandoffCommandPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{
    BoxFuture, DurabilityCommandPort, HandoffCommandPort, HandoffLeaseGrant, HandoffTicketGrant,
};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonDurabilityCommandAdapter {
    state: Arc<DaemonState>,
}

impl DaemonDurabilityCommandAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl DurabilityCommandPort for DaemonDurabilityCommandAdapter {
    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.state.latch_group_durability_unknown(group_id)
    }
}

pub(crate) struct DaemonHandoffCommandAdapter {
    state: Arc<DaemonState>,
}

impl DaemonHandoffCommandAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl HandoffCommandPort for DaemonHandoffCommandAdapter {
    fn request_lease<'a>(&'a self, group_id: &'a str) -> BoxFuture<'a, Option<HandoffLeaseGrant>> {
        Box::pin(async move {
            let (grant, _root_digest) = self.state.request_handoff_lease(group_id).await?;
            Some(HandoffLeaseGrant {
                lease_id: grant.lease_id,
                expires_at_unix: grant.expires_at_unix,
            })
        })
    }

    fn obtain_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Option<HandoffTicketGrant>> {
        Box::pin(async move {
            let grant = self.state.obtain_handoff_ticket_from_device(group_id, device_id).await?;
            Some(HandoffTicketGrant {
                lease_id: grant.lease_id.unwrap_or_default(),
                expires_at_unix: grant.expires_at_unix,
                target_device_id: grant.target_device_id.unwrap_or_default(),
            })
        })
    }

    fn release_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = self
                .state
                .release_handoff_ticket_from_device(group_id, device_id, target_device_id, lease_id)
                .await;
        })
    }
}
