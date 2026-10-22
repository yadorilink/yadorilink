//! `DaemonState`-backed [`HandoffTicketPort`] -- obtains/releases a
//! provisional handoff ticket over an established peer-to-peer session
//! (never the coordination plane's own HTTP API).

use std::sync::Arc;

use yadorilink_peer_session::peer_session::PeerHandoffTicketGrant;

use crate::application::ports::{BoxFuture, HandoffTicketPort};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonHandoffTicketAdapter {
    state: Arc<DaemonState>,
}

impl DaemonHandoffTicketAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl HandoffTicketPort for DaemonHandoffTicketAdapter {
    fn obtain_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Option<PeerHandoffTicketGrant>> {
        Box::pin(
            async move { self.state.obtain_handoff_ticket_from_device(group_id, device_id).await },
        )
    }

    fn release_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.state
                .release_handoff_ticket_from_device(group_id, device_id, target_device_id, lease_id)
                .await
        })
    }
}
