//! The coordination plane, seen as an address directory.
//!
//! `yadorilink_sync_substrate::AddressDirectory` is deliberately small: publish
//! this endpoint's addresses, resolve another endpoint's. That is the whole of
//! what this device owes iroh, because everything downstream of "where is this
//! endpoint" -- candidate collection, reflexive addresses, relays, NAT
//! traversal, path selection and path migration -- is iroh's already. Adding
//! any of it here would be reimplementing it.
//!
//! What is kept on this side is what iroh cannot know: who a peer is and
//! whether this device is allowed to talk to them. Identity needs no separate
//! binding, because an endpoint id IS the device's signing key and the netmap
//! already pins it.
//!
//! # Why the substrate no longer reads the netmap's candidate list
//!
//! It used to. That list is also the legacy peer-session transport's dial
//! targets: `peer_orchestrator` hands the same `peer.endpoints` to
//! `candidate_endpoints` and to `record_peer_candidate_addresses`. The two
//! transports listen on different sockets with different ALPNs, and a dial
//! that lands on the other one completes at the QUIC layer and is then refused
//! for an unknown ALPN -- a hard failure rather than a path worth retrying.
//! Measured every way round, one list cannot serve both: whichever socket it
//! names, the other transport breaks on it.
//!
//! So the two address spaces are separated at the source. The legacy transport
//! keeps the netmap's candidate list; the substrate gets this directory.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};

use yadorilink_sync_substrate::{AddressDirectory, PeerId};

use crate::peer_connectivity_runtime::PeerConnectivityRuntime;

/// Endpoint addresses this device knows, keyed by endpoint identity.
///
/// Held here rather than in `PeerConnectivityRuntime` because nothing else has any use
/// for it: the substrate is the only thing that dials by endpoint id.
#[derive(Debug, Default)]
struct Known {
    entries: std::collections::HashMap<[u8; 32], (Vec<SocketAddr>, Vec<String>)>,
}

/// Publishes and resolves substrate endpoint addresses.
pub struct CoordinationAddressDirectory {
    /// Only where this device's own substrate endpoint is published; nothing
    /// else of the daemon is needed here. Weak so this directory, which the
    /// device's live iroh endpoint owns, never keeps that state alive after
    /// the daemon has dropped it.
    connectivity: Weak<PeerConnectivityRuntime>,
    known: Mutex<Known>,
}

impl std::fmt::Debug for CoordinationAddressDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoordinationAddressDirectory")
    }
}

impl CoordinationAddressDirectory {
    pub fn new(connectivity: &Arc<PeerConnectivityRuntime>) -> Arc<Self> {
        Arc::new(Self {
            connectivity: Arc::downgrade(connectivity),
            known: Mutex::new(Known::default()),
        })
    }

    /// Records where `peer` answers, as the coordination plane reported it.
    ///
    /// Called when a netmap push carries substrate addresses for a device.
    /// Raising the peer session driver's own "peer reachable" event here
    /// would be the wrong layer: iroh decides when an address is usable, and
    /// the driver already learns reachability from the netmap itself.
    pub fn record(&self, peer: PeerId, direct: Vec<SocketAddr>, relays: Vec<String>) {
        let mut known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        known.entries.insert(*peer.as_bytes(), (direct, relays));
    }

    /// Forgets where `peer` answers, once its device has been revoked, so
    /// nothing this device knows still names an address for it.
    pub fn forget(&self, peer: PeerId) {
        let mut known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        known.entries.remove(peer.as_bytes());
    }
}

impl AddressDirectory for CoordinationAddressDirectory {
    fn publish(&self, peer: PeerId, direct: Vec<SocketAddr>, relays: Vec<String>) {
        // Recorded for this device too, so a loopback deployment where every
        // peer is this process resolves without a round trip through the
        // plane. Harmless elsewhere: resolving your own id is something iroh
        // never asks for.
        self.record(peer, direct.clone(), relays.clone());
        let Some(connectivity) = self.connectivity.upgrade() else {
            return;
        };
        connectivity.publish_substrate_endpoint(direct, relays);
    }

    fn resolve(&self, peer: PeerId) -> Option<(Vec<SocketAddr>, Vec<String>)> {
        let known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        known.entries.get(peer.as_bytes()).cloned()
    }
}
