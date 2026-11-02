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
    /// Raised each time an address record arrives, for whatever waits on a peer's relay becoming known.
    recorded: tokio::sync::Notify,
    /// Which peer's record arrived, for lookups that stay open for later records.
    changed: tokio::sync::broadcast::Sender<PeerId>,
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
            recorded: tokio::sync::Notify::new(),
            changed: tokio::sync::broadcast::channel(64).0,
        })
    }

    /// Records where `peer` answers, as the coordination plane reported it.
    ///
    /// Called when a netmap push carries substrate addresses for a device.
    /// Raising the peer session driver's own "peer reachable" event here
    /// would be the wrong layer: iroh decides when an address is usable, and
    /// the driver already learns reachability from the netmap itself.
    pub fn record(&self, peer: PeerId, direct: Vec<SocketAddr>, relays: Vec<String>) {
        let entry = (direct, relays);
        let mut known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        // A netmap push repeats what is already known far more often than it changes it;
        // waking what waits on a change for those would cost idle wakeups for nothing.
        if known.entries.get(peer.as_bytes()) == Some(&entry) {
            return;
        }
        known.entries.insert(*peer.as_bytes(), entry);
        drop(known);
        self.recorded.notify_one();
        let _ = self.changed.send(peer);
    }

    /// Whether the coordination plane has told this device a relay `peer` can be reached through
    /// that a connection can use (an unparseable URL is not one).
    pub fn knows_relay_of(&self, peer: &PeerId) -> bool {
        let known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        known.entries.get(peer.as_bytes()).is_some_and(|(_, relays)| {
            relays.iter().any(|relay| yadorilink_sync_substrate::is_usable_relay_url(relay))
        })
    }

    /// Resolves the next time a record arrives.
    pub async fn next_record(&self) {
        self.recorded.notified().await;
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

    fn changes(&self, peer: PeerId) -> Option<yadorilink_sync_substrate::ChangeStream> {
        use tokio::sync::broadcast::error::RecvError;
        let receiver = self.changed.subscribe();
        Some(Box::pin(futures_util::stream::unfold(receiver, move |mut receiver| async move {
            loop {
                match receiver.recv().await {
                    Ok(changed) if changed == peer => return Some(((), receiver)),
                    Ok(_) => {}
                    // Missed some: look again rather than guess whether ours was among them.
                    Err(RecvError::Lagged(_)) => return Some(((), receiver)),
                    Err(RecvError::Closed) => return None,
                }
            }
        })))
    }

    fn resolve(&self, peer: PeerId) -> Option<(Vec<SocketAddr>, Vec<String>)> {
        let known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        known.entries.get(peer.as_bytes()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt as _;
    use std::time::Duration;

    fn directory() -> CoordinationAddressDirectory {
        CoordinationAddressDirectory {
            connectivity: Weak::new(),
            known: Mutex::new(Known::default()),
            recorded: tokio::sync::Notify::new(),
            changed: tokio::sync::broadcast::channel(8).0,
        }
    }

    async fn signals(stream: &mut yadorilink_sync_substrate::ChangeStream) -> usize {
        let mut count = 0;
        while tokio::time::timeout(Duration::from_millis(50), stream.next()).await.is_ok() {
            count += 1;
        }
        count
    }

    /// A netmap push that repeats what is already known wakes nothing; a change does, and only
    /// for the peer it concerns.
    #[tokio::test]
    async fn only_a_changed_record_signals_the_lookups_waiting_on_that_peer() {
        let dir = directory();
        let peer = PeerId::from_bytes([1; 32]);
        let other = PeerId::from_bytes([2; 32]);
        let lan: SocketAddr = "192.168.0.7:4000".parse().unwrap();
        let mut stream = dir.changes(peer).expect("this directory signals changes");

        dir.record(peer, vec![lan], Vec::new());
        dir.record(peer, vec![lan], Vec::new());
        dir.record(peer, vec![lan], Vec::new());
        assert_eq!(signals(&mut stream).await, 1, "a repeated record must not signal again");

        dir.record(peer, vec![lan], vec!["https://relay.example./".to_string()]);
        dir.record(other, vec![lan], Vec::new());
        assert_eq!(
            signals(&mut stream).await,
            1,
            "a new relay signals once, another peer not at all"
        );
        assert!(dir.knows_relay_of(&peer));
        assert!(!dir.knows_relay_of(&other));
    }
}
