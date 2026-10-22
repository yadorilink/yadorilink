//! Owns the transport stack and the per-peer sessions that ride it.
//!
//! Nothing here drives a replication protocol: history moves over native
//! replication, which schedules itself. What this holds together is the
//! endpoint, the inbound lane routing and the sessions blocks and service
//! RPCs travel over, so they live and die with the daemon's stack.

use std::sync::Arc;

use crate::daemon_state::DaemonState;

use super::sync_stack::SyncStack;

/// Holds a running stack and its peer sessions.
pub struct PeerSessionDriver {
    stack: Arc<SyncStack>,
    /// Keeps a peer session for every authorized peer this stack's endpoint
    /// reaches. Held here because sessions ride this stack's lanes: when the
    /// driver goes, so does every session over it.
    sessions: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for PeerSessionDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerSessionDriver")
    }
}

impl PeerSessionDriver {
    /// Start serving `stack`'s lanes and keeping `state`'s peer sessions.
    pub fn start(state: Arc<DaemonState>, stack: Arc<SyncStack>) -> Arc<Self> {
        // Inbound blocks and service RPCs reach their session through the
        // stack; outbound ones are attached at registration.
        stack.serve_peer_lanes();
        // The sessions those streams are served by, and that hydration,
        // repair and the convergence executor draw their content from: one
        // per authorized peer this endpoint can reach.
        let sessions = crate::peer_connectivity_runtime::keep_peer_sessions(&state, &stack);
        Arc::new(Self { stack, sessions })
    }

    /// The stack this driver holds, for callers that need to reach it.
    pub fn stack(&self) -> &Arc<SyncStack> {
        &self.stack
    }
}

impl Drop for PeerSessionDriver {
    fn drop(&mut self) {
        self.sessions.abort();
    }
}
