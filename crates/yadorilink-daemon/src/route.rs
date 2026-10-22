//! Which kind of path carries a connected peer's traffic.
//!
//! **Standing invariant: `Durability != Connectivity`.** A session being
//! reachable is not evidence the data moving over it landed durably anywhere
//! -- that is exactly what the native admission/materialization layer, not
//! connectivity, is responsible for proving. `RouteKind` and full-replica
//! status (`PeerAuthorityState::peer_group_is_full_replica`) are independent
//! axes, never inferred from one another. A relayed peer is as connected as a
//! direct one, and no more or less trusted: a relay server carries packets
//! and decides nothing.

/// Which path a peer connection is actually using. Carried by
/// `PeerReachability::Connected` so a caller can distinguish path kinds
/// without that distinction implying anything about durability (see this
/// module's own doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Endpoint to endpoint, with no server in between.
    Direct,
    /// Through a relay server, because no direct path is up (yet): iroh
    /// starts most connections on a relay and moves them to a direct path
    /// once hole punching succeeds.
    Relay,
}

impl RouteKind {
    /// Stable wire/status slug: "direct" | "relay".
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Direct => "direct",
            RouteKind::Relay => "relay",
        }
    }
}
