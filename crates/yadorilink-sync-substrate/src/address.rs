//! How to reach a peer.
//!
//! Address information is supplied by the Yadori coordination plane, which
//! already knows group membership. The substrate registers no address lookup
//! service of its own, so there is no third-party directory that convergence
//! could come to depend on.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::peer::PeerId;

/// A peer's identity together with the paths currently believed to reach it.
///
/// An address is a hint, never an authorization: reaching a peer by one path
/// rather than another has no bearing on what that peer is allowed to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAddress {
    peer: PeerId,
    direct: BTreeSet<SocketAddr>,
    relays: BTreeSet<String>,
}

impl PeerAddress {
    /// A peer with no known paths. Dialling this succeeds only if the
    /// transport already holds a path from an earlier connection.
    pub fn new(peer: PeerId) -> Self {
        Self { peer, direct: BTreeSet::new(), relays: BTreeSet::new() }
    }

    /// Add directly reachable socket addresses.
    pub fn with_direct(mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.direct.extend(addrs);
        self
    }

    /// Add relay URLs to fall back to when no direct path can be established.
    pub fn with_relays(mut self, relays: impl IntoIterator<Item = String>) -> Self {
        self.relays.extend(relays);
        self
    }

    pub fn peer(&self) -> PeerId {
        self.peer
    }

    pub fn direct_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.direct.iter()
    }

    pub fn relay_urls(&self) -> impl Iterator<Item = &str> {
        self.relays.iter().map(String::as_str)
    }
}

impl From<PeerId> for PeerAddress {
    fn from(peer: PeerId) -> Self {
        Self::new(peer)
    }
}
