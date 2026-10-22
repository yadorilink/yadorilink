//! The netmap as the sync path's peer directory.
//!
//! The two questions a sync session needs answered about the peer on the other
//! end — who is this, and may they be told about this group — are both already
//! answered by the netmap this device maintains. Nothing new has to be
//! published for the reconciliation path to work.
//!
//! *Who is this* resolves because the endpoint identity is the device's own
//! Ed25519 signing key (see `yadorilink_sync_substrate`'s own note on why that
//! is the only option that does not invent a third identity), and the netmap
//! already pins each peer's signing key. So the binding between transport
//! identity and device identity is not something this path has to invent, ask
//! for, or trust the peer to assert — it is a reverse lookup over keys an
//! authenticated netmap already supplied.
//!
//! *May they be told* is a conjunction, not a single lookup. The peer must be
//! authorized for the group, and this device must currently be able to serve
//! that group at all — a group whose policy has gone stale or has not loaded
//! this run is withheld from everyone, however well authorized they are. Both
//! halves come from [`DaemonState`]: `group_is_servable` and `peer_is_writer`,
//! the same two the legacy announcement path uses, called rather than
//! re-derived so the two paths cannot drift into disagreeing.
//!
//! Both are answered fresh on every call, deliberately. A revocation must stop
//! disclosure at once, and a peer pinned after a session opened must start
//! being answerable without anything having to notice and refresh.

use std::sync::Arc;

use crate::daemon_state::DaemonState;

use yadorilink_lane_ports::PeerDirectory;

/// Resolves peers through this device's live netmap.
#[derive(Clone)]
pub struct DaemonPeerDirectory {
    state: Arc<DaemonState>,
}

impl DaemonPeerDirectory {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl std::fmt::Debug for DaemonPeerDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DaemonPeerDirectory")
    }
}

impl PeerDirectory for DaemonPeerDirectory {
    fn device_for_endpoint(&self, endpoint: &[u8; 32]) -> Option<String> {
        // Not inferred from the connection: this is the key the netmap pinned
        // for some device, matched against the key that actually terminated
        // the TLS handshake. A peer asserting a device identity over its own
        // transport would be asserting the thing being checked; here it has
        // to hold the private half of a key an authenticated netmap already
        // attributed to that device.
        self.state.authority.device_id_for_signing_key(endpoint)
    }

    fn is_authorized(&self, device_id: &str, group_id: &str) -> bool {
        // Local servability first: it is the cheaper check and the one that
        // fails closed for reasons having nothing to do with this peer.
        self.state.group_is_servable(group_id)
            && self.state.authority.peer_is_writer(device_id, group_id)
    }
}
