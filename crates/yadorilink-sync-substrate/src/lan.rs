//! Where an already-authorized peer answers on the local network, found
//! without the coordination plane.
//!
//! The coordination directory is how a device normally learns where a peer
//! is. When the plane, the relays or the internet are unreachable, two
//! devices on the same LAN would otherwise be unable to find each other at
//! all, although nothing between them is broken. mDNS answers that one
//! question -- where does this endpoint currently answer -- and nothing else.
//!
//! # A LAN announcement is not authority
//!
//! Anyone on the local network can announce anything. An announcement names
//! an endpoint id and some addresses, and says nothing about whether this
//! device has any business talking to that endpoint. So the only way an mDNS
//! answer reaches iroh is through [`LanLookup::resolve`], which first asks the
//! authorization policy the device supplied, and answers nothing at all for
//! an endpoint that policy does not accept. Nothing here subscribes to passive
//! discoveries either: hearing an announcement never starts a dial. A dial
//! starts only from a peer the device already chose to reach, and mDNS can at
//! most tell it where that peer is.
//!
//! First pairing is deliberately out of scope: a device that has never been
//! told about a peer by the coordination plane has no policy that accepts it,
//! so it can find nobody here.

use std::sync::Arc;

use iroh::address_lookup::{AddressLookup, EndpointData, Error, Item};
use n0_future::boxed::BoxStream;
use n0_future::StreamExt;

use crate::admission::PeerAdmission;
use crate::peer::PeerId;

/// The mDNS service name endpoints advertise under.
///
/// Our own rather than iroh's shared default, so an unrelated iroh
/// application on the same network neither sees these endpoints in its
/// listing nor fills ours with its own.
const SERVICE_NAME: &str = "yadorilink";

/// A local-network address source, answering only for endpoints `authorized`
/// accepts.
///
/// `source` is mDNS in production. It is a type parameter only so a test can
/// stand a scripted answer in for multicast, which a test host may not
/// deliver; the filter in front of it is the same either way.
#[derive(Debug)]
pub(crate) struct LanLookup<L> {
    source: L,
    authorized: Arc<dyn PeerAdmission>,
}

impl<L: AddressLookup> LanLookup<L> {
    pub(crate) fn new(source: L, authorized: Arc<dyn PeerAdmission>) -> Self {
        Self { source, authorized }
    }
}

impl<L: AddressLookup> AddressLookup for LanLookup<L> {
    /// Advertises this endpoint's own addresses. Saying where this device
    /// answers grants nothing: a peer that finds it still has to pass
    /// admission on connect.
    fn publish(&self, data: &EndpointData) {
        self.source.publish(data);
    }

    fn resolve(&self, endpoint_id: iroh::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        // Asked live on every lookup, so a peer revoked after it was
        // discovered stops resolving from that moment on.
        if !self.authorized.admit(&PeerId::from_bytes(*endpoint_id.as_bytes())) {
            tracing::trace!(%endpoint_id, "not resolving an unauthorized endpoint on the LAN");
            return None;
        }
        let answers = self.source.resolve(endpoint_id)?;
        // Only answers about the endpoint that was asked for. An answer
        // naming some other endpoint is one this filter never judged.
        Some(Box::pin(answers.filter(move |answer| match answer {
            Ok(item) => item.endpoint_id() == endpoint_id,
            Err(_) => true,
        })))
    }
}

/// The mDNS source for the endpoint `local`, or `None` when this host's
/// network cannot run it.
///
/// Not being able to use the LAN is not a reason to refuse to start: every
/// other path to a peer is unaffected, so this degrades to "no LAN lookup"
/// and says so.
pub(crate) fn mdns(local: iroh::EndpointId) -> Option<iroh_mdns_address_lookup::MdnsAddressLookup> {
    match iroh_mdns_address_lookup::MdnsAddressLookup::builder()
        .service_name(SERVICE_NAME)
        .build(local)
    {
        Ok(mdns) => Some(mdns),
        Err(err) => {
            tracing::warn!(%err, "local-network peer lookup unavailable on this host");
            None
        }
    }
}

#[cfg(test)]
mod tests;
