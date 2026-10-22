//! Where a peer is, asked of the coordination plane.
//!
//! # Why this is a lookup and not a list of addresses
//!
//! The substrate used to be handed a peer's addresses from outside: the
//! coordination plane published one endpoint list per device, the daemon read
//! it out of the netmap and passed it down as direct candidates. That list is
//! also what the legacy peer-session transport dials, and the two speak
//! different protocols on different sockets. Neither consumer could tell which
//! entry belonged to it, and a dial landing on the other one completes at the
//! QUIC layer and is then refused for an unknown ALPN -- a hard failure, not a
//! path worth retrying. Measured every way round, one list cannot serve both:
//! whichever socket it names, the other transport breaks on it.
//!
//! So the substrate no longer accepts addresses. It is given a *directory* and
//! asks it, which is the shape iroh already has: publish this endpoint's own
//! addresses when they change, resolve someone else's from their id. Reaching
//! an endpoint -- direct candidates, reflexive addresses, relays, NAT
//! traversal, which path wins and when to change paths -- belongs to iroh, and
//! re-deriving any of it here would be rebuilding what it already does.
//!
//! What stays on this side is the part iroh cannot know: who a peer is, and
//! whether we are allowed to talk to them. Identity needs no extra binding --
//! an endpoint id IS the device's signing key, the same key the coordination
//! plane already pins -- so the directory is only a place to look up where
//! that key currently answers.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::peer::PeerId;

/// Where endpoint addresses are published and looked up.
///
/// Implemented by whatever owns the coordination plane. Deliberately in terms
/// of plain sockets and relay URLs: nothing above this crate should have to
/// name an iroh type to answer "where is this peer".
pub trait AddressDirectory: Send + Sync + std::fmt::Debug + 'static {
    /// This endpoint's own addresses changed. Fire and forget -- iroh calls
    /// this from its own task and cannot wait for a round trip, so an
    /// implementation that needs to do I/O should spawn.
    fn publish(&self, peer: PeerId, direct: Vec<SocketAddr>, relays: Vec<String>);

    /// Where `peer` currently answers, if this directory knows.
    ///
    /// `None` and an empty answer mean the same thing to iroh: nothing to add
    /// to what it already knows. Neither is an error, because a peer this
    /// device has not been told about yet is ordinary.
    fn resolve(&self, peer: PeerId) -> Option<(Vec<SocketAddr>, Vec<String>)>;
}

/// Adapts an [`AddressDirectory`] to iroh's own address-lookup interface.
///
/// The whole type is this adapter: no caching, no retry, no scheduling. iroh
/// decides when to publish and when to resolve, and doing any of that again
/// here would be the duplication this module exists to remove.
#[derive(Debug, Clone)]
pub(crate) struct DirectoryLookup {
    directory: Arc<dyn AddressDirectory>,
    /// This endpoint's own id. `EndpointData` carries addresses and no
    /// identity, because iroh only ever publishes the local endpoint's -- so
    /// the id has to come from construction rather than from the callback.
    local: PeerId,
}

impl DirectoryLookup {
    pub(crate) fn new(directory: Arc<dyn AddressDirectory>, local: PeerId) -> Self {
        Self { directory, local }
    }
}

impl iroh::address_lookup::AddressLookup for DirectoryLookup {
    fn publish(&self, data: &iroh::address_lookup::EndpointData) {
        let direct: Vec<SocketAddr> = data.ip_addrs().copied().collect();
        let relays: Vec<String> = data.relay_urls().map(ToString::to_string).collect();
        self.directory.publish(self.local, direct, relays);
    }

    fn resolve(
        &self,
        endpoint_id: iroh::EndpointId,
    ) -> Option<
        n0_future::boxed::BoxStream<
            Result<iroh::address_lookup::Item, iroh::address_lookup::Error>,
        >,
    > {
        let (direct, relays) =
            self.directory.resolve(PeerId::from_bytes(*endpoint_id.as_bytes()))?;
        // Judged on what survives parsing, not on what arrived. A directory
        // holding one unparseable relay URL and nothing else is not an answer,
        // and returning it as one hands iroh an endpoint with no usable path --
        // indistinguishable, to it, from a peer that really is reachable.
        let usable_relays: Vec<iroh::RelayUrl> = relays
            .into_iter()
            .filter_map(|relay| match relay.parse::<iroh::RelayUrl>() {
                Ok(url) => Some(url),
                Err(_) => {
                    tracing::debug!(%relay, "dropping an unparseable relay URL");
                    None
                }
            })
            .collect();
        if direct.is_empty() && usable_relays.is_empty() {
            return None;
        }
        let mut info = iroh::address_lookup::EndpointInfo::new(endpoint_id).with_ip_addrs(direct);
        for url in usable_relays {
            info = info.with_relay_url(url);
        }
        let item = iroh::address_lookup::Item::new(info, PROVENANCE, None);
        Some(Box::pin(n0_future::stream::once(Ok(item))))
    }
}

/// Names this lookup in iroh's own logs and metrics.
const PROVENANCE: &str = "yadori-coordination";

#[cfg(test)]
mod tests;
