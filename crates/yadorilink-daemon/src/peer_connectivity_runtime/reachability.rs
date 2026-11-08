//! A peer's reachability, as this device's iroh connections to it show it.
//!
//! The only producer of [`PeerReachability`]. What `yadorilink status`, the
//! health count and "available now" say about a peer is read from here, and
//! everything here is fed by the iroh endpoint's own reports: a dial starting
//! and ending, a connection being accepted, and each connection's selected
//! path changing or the connection going away.
//!
//! ```text
//!   any connection with a direct path selected   Connected(Direct)
//!   else any with a relay path selected           Connected(Relay)
//!   else a connection with no path yet, or a dial Connecting
//!   else the last dial failed                     Unreachable(why)
//!   else                                          nothing: not listed
//! ```
//!
//! A peer usually has more than one connection at once: reconciliation dials
//! one per pass, the bulk lanes keep another, and the peer's own dials arrive
//! as accepted ones. Any of them carrying traffic makes the peer reachable,
//! which is why this is kept per connection and folded, rather than being
//! whatever the last event said.
//!
//! Reachability is not authorization and not durability. Being listed here
//! says only that bytes can move; whether the peer may be told anything is
//! `PeerAuthorityState`'s question, and whether anything it holds is safe is
//! the custody layer's.

use std::collections::HashMap;

use yadorilink_sync_substrate::{Carrier, DialFailure, PeerId};

use crate::peer_registry::{PeerReachability, UnreachableCategory};
use crate::route::RouteKind;

/// One connection to a peer, for as long as it is followed.
pub(crate) type LinkId = u64;

/// What a user is told a failed dial means.
pub(super) fn unreachable_because(failure: DialFailure) -> UnreachableCategory {
    match failure {
        DialFailure::NoAddress => UnreachableCategory::NoCandidates,
        DialFailure::Refused => UnreachableCategory::HandshakeRefused,
        DialFailure::NoResponse => UnreachableCategory::NoResponse,
    }
}

/// Which end of a version mismatch has to update: the peer's protocol version is newer than
/// this device's (this device is the old one), or older.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSkew {
    PeerNewer,
    PeerOlder,
}

impl VersionSkew {
    /// The skew between the peer's protocol version and ours; `None` when they match.
    pub fn between(theirs: u32, ours: u32) -> Option<Self> {
        match theirs.cmp(&ours) {
            std::cmp::Ordering::Greater => Some(Self::PeerNewer),
            std::cmp::Ordering::Less => Some(Self::PeerOlder),
            std::cmp::Ordering::Equal => None,
        }
    }
}

/// Every peer's connections and dials, and the reachability they add up to.
#[derive(Debug, Default)]
pub(super) struct LinkReachability {
    devices: HashMap<String, DeviceLinks>,
    /// Dials in flight, by the endpoint dialled, with the device it was
    /// resolved to when the dial started. A dial's end is matched here rather
    /// than resolved again, so a key withdrawn mid-dial cannot leave the dial
    /// counted forever.
    dials: HashMap<PeerId, (String, u32)>,
    next_link: LinkId,
}

#[derive(Debug, Default)]
struct DeviceLinks {
    dialing: u32,
    failure: Option<UnreachableCategory>,
    /// Live connections.
    links: HashMap<LinkId, LinkState>,
}

#[derive(Debug)]
struct LinkState {
    /// The kind of path this connection has selected, if any.
    carrier: Option<Carrier>,
    /// The transport's id for this connection, which a lane's report names it by.
    connection: usize,
    /// This connection opened a lane whose hello speaks another protocol version. The device is
    /// reachable, so this is not a reachability: it is a fact about this connection, and it
    /// ends with it.
    incompatible: Option<VersionSkew>,
}

impl DeviceLinks {
    fn reachability(&self) -> Option<PeerReachability> {
        let selected = |kind| self.links.values().any(|link| link.carrier == Some(kind));
        if selected(Carrier::Direct) {
            return Some(PeerReachability::Connected(RouteKind::Direct));
        }
        if selected(Carrier::Relay) {
            return Some(PeerReachability::Connected(RouteKind::Relay));
        }
        if !self.links.is_empty() || self.dialing > 0 {
            return Some(PeerReachability::Connecting);
        }
        self.failure.map(PeerReachability::Unreachable)
    }
}

impl LinkReachability {
    pub(super) fn dial_started(&mut self, device: &str, peer: PeerId) {
        let entry = self.dials.entry(peer).or_insert_with(|| (device.to_string(), 0));
        entry.1 += 1;
        let device = entry.0.clone();
        self.devices.entry(device).or_default().dialing += 1;
    }

    /// Ends one dial to `peer`, returning the device it was for, or `None`
    /// when no dial to `peer` is being tracked (the device was revoked while
    /// it ran).
    fn dial_ended(&mut self, peer: PeerId) -> Option<String> {
        let (device, remaining) = {
            let entry = self.dials.get_mut(&peer)?;
            entry.1 -= 1;
            (entry.0.clone(), entry.1)
        };
        if remaining == 0 {
            self.dials.remove(&peer);
        }
        if let Some(links) = self.devices.get_mut(&device) {
            links.dialing = links.dialing.saturating_sub(1);
        }
        Some(device)
    }

    pub(super) fn dial_failed(&mut self, peer: PeerId, why: UnreachableCategory) {
        if let Some(device) = self.dial_ended(peer) {
            if let Some(links) = self.devices.get_mut(&device) {
                links.failure = Some(why);
            }
            self.prune(&device);
        }
    }

    /// Ends a dial to `peer` that connected, returning the device the new
    /// connection belongs to.
    pub(super) fn dial_connected(&mut self, peer: PeerId) -> Option<String> {
        self.dial_ended(peer)
    }

    pub(super) fn link_up(
        &mut self,
        device: &str,
        carrier: Option<Carrier>,
        connection: usize,
    ) -> LinkId {
        let id = self.next_link;
        self.next_link += 1;
        let links = self.devices.entry(device.to_string()).or_default();
        links.failure = None;
        links.links.insert(id, LinkState { carrier, connection, incompatible: None });
        id
    }

    /// Records the path `link` now uses. A connection this no longer tracks
    /// -- closed, or its device revoked -- is not brought back.
    pub(super) fn carrier_changed(&mut self, device: &str, link: LinkId, carrier: Option<Carrier>) {
        if let Some(slot) = self.devices.get_mut(device).and_then(|d| d.links.get_mut(&link)) {
            slot.carrier = carrier;
        }
    }

    pub(super) fn link_closed(&mut self, device: &str, link: LinkId) {
        if let Some(links) = self.devices.get_mut(device) {
            links.links.remove(&link);
        }
        self.prune(device);
    }

    /// Drops everything known about `device`: it is no longer a peer.
    pub(super) fn forget(&mut self, device: &str) {
        self.devices.remove(device);
        self.dials.retain(|_, (dialled, _)| dialled != device);
    }

    /// Records that `device`, over its live connection `connection`, speaks another protocol
    /// version. A connection that is not live is not marked: nothing says it is reachable.
    pub(super) fn mark_incompatible(&mut self, device: &str, connection: usize, skew: VersionSkew) {
        if let Some(link) = self
            .devices
            .get_mut(device)
            .and_then(|d| d.links.values_mut().find(|l| l.connection == connection))
        {
            link.incompatible = Some(skew);
        }
    }

    /// Whether a live connection to `device` is marked: the mark leaves with its connection.
    pub(super) fn is_incompatible(&self, device: &str) -> bool {
        self.version_skew(device).is_some()
    }

    /// Which side is older, when a live connection to `device` is marked.
    pub(super) fn version_skew(&self, device: &str) -> Option<VersionSkew> {
        self.devices.get(device).and_then(|d| d.links.values().find_map(|l| l.incompatible))
    }

    pub(super) fn get(&self, device: &str) -> Option<PeerReachability> {
        self.devices.get(device).and_then(DeviceLinks::reachability)
    }

    pub(super) fn all(&self) -> Vec<(String, PeerReachability)> {
        self.devices
            .iter()
            .filter_map(|(device, links)| links.reachability().map(|r| (device.clone(), r)))
            .collect()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn open_links(&self, device: &str) -> Vec<LinkId> {
        self.devices.get(device).map(|d| d.links.keys().copied().collect()).unwrap_or_default()
    }

    /// Removes `device`'s entry once it has nothing left to report, so a
    /// peer whose connections all ended is not listed.
    fn prune(&mut self, device: &str) {
        if self.devices.get(device).is_some_and(|links| links.reachability().is_none()) {
            self.devices.remove(device);
        }
    }
}

/// Every peer with something to report, plus every device the account replaced -- always listed,
/// as unreachable for being replaced ([`UnreachableCategory::DeviceReplaced`]) whatever its links
/// did before it was refused: the typed reason, not a silent absence.
pub(crate) fn peers_with_replaced(
    links: Vec<(String, PeerReachability)>,
    authority: &crate::daemon_state::PeerAuthorityState,
) -> Vec<(String, PeerReachability)> {
    let replaced = authority.superseded_snapshot();
    let mut all: Vec<_> = links
        .into_iter()
        .filter(|(device, _)| !replaced.iter().any(|(old, _)| old == device))
        .collect();
    all.extend(replaced.into_iter().map(|(old, _)| {
        (
            old,
            PeerReachability::Unreachable(
                crate::peer_registry::UnreachableCategory::DeviceReplaced,
            ),
        )
    }));
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: &str = "device-b";

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    #[test]
    fn a_peer_with_nothing_observed_is_not_listed() {
        let links = LinkReachability::default();
        assert_eq!(links.get(DEVICE), None);
        assert!(links.all().is_empty());
    }

    #[test]
    fn a_dial_in_flight_reads_connecting_and_its_failure_reads_unreachable() {
        let mut links = LinkReachability::default();
        links.dial_started(DEVICE, peer(1));
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connecting));

        links.dial_failed(peer(1), UnreachableCategory::NoResponse);
        assert_eq!(
            links.get(DEVICE),
            Some(PeerReachability::Unreachable(UnreachableCategory::NoResponse)),
            "the reason stays listed so the user can see it"
        );
    }

    #[test]
    fn a_connection_reads_as_its_selected_path_and_direct_wins_over_relay() {
        let mut links = LinkReachability::default();
        let relayed = links.link_up(DEVICE, Some(Carrier::Relay), 0);
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connected(RouteKind::Relay)));

        let direct = links.link_up(DEVICE, None, 0);
        assert_eq!(
            links.get(DEVICE),
            Some(PeerReachability::Connected(RouteKind::Relay)),
            "a second connection with no path yet does not hide the one carrying traffic"
        );
        links.carrier_changed(DEVICE, direct, Some(Carrier::Direct));
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connected(RouteKind::Direct)));

        links.link_closed(DEVICE, direct);
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connected(RouteKind::Relay)));
        links.link_closed(DEVICE, relayed);
        assert_eq!(links.get(DEVICE), None, "no connection and no dial: not listed");
    }

    #[test]
    fn a_connection_moving_from_relay_to_direct_is_followed() {
        let mut links = LinkReachability::default();
        let link = links.link_up(DEVICE, Some(Carrier::Relay), 0);
        links.carrier_changed(DEVICE, link, Some(Carrier::Direct));
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connected(RouteKind::Direct)));
    }

    #[test]
    fn a_connection_clears_an_earlier_failure() {
        let mut links = LinkReachability::default();
        links.dial_started(DEVICE, peer(1));
        links.dial_failed(peer(1), UnreachableCategory::NoCandidates);
        let link = links.link_up(DEVICE, Some(Carrier::Direct), 0);
        links.link_closed(DEVICE, link);
        assert_eq!(links.get(DEVICE), None, "the old failure does not come back");
    }

    #[test]
    fn a_dial_that_connects_is_no_longer_counted_as_dialling() {
        let mut links = LinkReachability::default();
        links.dial_started(DEVICE, peer(1));
        assert_eq!(links.dial_connected(peer(1)).as_deref(), Some(DEVICE));
        let link = links.link_up(DEVICE, Some(Carrier::Direct), 0);
        links.link_closed(DEVICE, link);
        assert_eq!(links.get(DEVICE), None);
    }

    #[test]
    fn a_forgotten_device_is_not_brought_back_by_its_old_connections_or_dials() {
        let mut links = LinkReachability::default();
        links.dial_started(DEVICE, peer(1));
        let link = links.link_up(DEVICE, Some(Carrier::Direct), 0);

        links.forget(DEVICE);
        assert_eq!(links.get(DEVICE), None);

        links.carrier_changed(DEVICE, link, Some(Carrier::Relay));
        links.dial_failed(peer(1), UnreachableCategory::NoResponse);
        links.link_closed(DEVICE, link);
        assert_eq!(links.get(DEVICE), None);
        assert!(links.all().is_empty());
    }

    #[test]
    fn a_connected_device_that_spoke_another_version_is_incompatible_and_still_connected() {
        let mut links = LinkReachability::default();
        links.link_up(DEVICE, Some(Carrier::Direct), 0);
        assert!(!links.is_incompatible(DEVICE));

        links.mark_incompatible(DEVICE, 0, VersionSkew::PeerNewer);
        assert!(links.is_incompatible(DEVICE));
        assert_eq!(
            links.get(DEVICE),
            Some(PeerReachability::Connected(RouteKind::Direct)),
            "it is online: incompatible is never a reachability"
        );
    }

    #[test]
    fn the_incompatible_mark_leaves_with_its_connection_while_another_remains() {
        let mut links = LinkReachability::default();
        let old = links.link_up(DEVICE, Some(Carrier::Direct), 1);
        links.link_up(DEVICE, Some(Carrier::Direct), 2);

        links.mark_incompatible(DEVICE, 1, VersionSkew::PeerNewer);
        assert!(links.is_incompatible(DEVICE));
        links.mark_incompatible(DEVICE, 99, VersionSkew::PeerNewer);

        links.link_closed(DEVICE, old);
        assert!(!links.is_incompatible(DEVICE), "the marked connection is gone");
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connected(RouteKind::Direct)));
    }

    #[test]
    fn an_incompatible_device_whose_path_is_not_selected_yet_reads_connecting_never_unreachable() {
        let mut links = LinkReachability::default();
        let link = links.link_up(DEVICE, None, 0);
        links.mark_incompatible(DEVICE, 0, VersionSkew::PeerNewer);
        assert!(links.is_incompatible(DEVICE));
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connecting));

        links.carrier_changed(DEVICE, link, Some(Carrier::Relay));
        assert_eq!(links.get(DEVICE), Some(PeerReachability::Connected(RouteKind::Relay)));
    }

    #[test]
    fn incompatibility_ends_with_the_connections_and_is_not_invented_for_a_device_without_one() {
        let mut links = LinkReachability::default();
        links.mark_incompatible(DEVICE, 0, VersionSkew::PeerNewer);
        assert!(!links.is_incompatible(DEVICE), "no connection: nothing says it is reachable");

        let link = links.link_up(DEVICE, Some(Carrier::Direct), 0);
        links.mark_incompatible(DEVICE, 0, VersionSkew::PeerNewer);
        links.dial_started(DEVICE, peer(1));
        links.link_closed(DEVICE, link);
        assert!(!links.is_incompatible(DEVICE), "the old connection's verdict does not outlive it");

        links.dial_failed(peer(1), UnreachableCategory::NoResponse);
        assert_eq!(
            links.get(DEVICE),
            Some(PeerReachability::Unreachable(UnreachableCategory::NoResponse))
        );
    }

    #[test]
    fn an_unrelated_failed_dial_does_not_erase_a_live_connections_verdict() {
        let mut links = LinkReachability::default();
        links.link_up(DEVICE, Some(Carrier::Direct), 0);
        links.mark_incompatible(DEVICE, 0, VersionSkew::PeerNewer);
        links.dial_started(DEVICE, peer(1));
        links.dial_failed(peer(1), UnreachableCategory::NoResponse);
        assert!(links.is_incompatible(DEVICE));
    }

    #[test]
    fn every_listed_peer_is_reported_once() {
        let mut links = LinkReachability::default();
        links.link_up("a", Some(Carrier::Direct), 0);
        links.link_up("a", Some(Carrier::Relay), 0);
        links.dial_started("b", peer(2));
        let mut all = links.all();
        all.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            all,
            vec![
                ("a".to_string(), PeerReachability::Connected(RouteKind::Direct)),
                ("b".to_string(), PeerReachability::Connecting),
            ]
        );
    }

    #[test]
    fn the_skew_names_the_older_end_and_matching_versions_have_none() {
        assert_eq!(VersionSkew::between(6, 5), Some(VersionSkew::PeerNewer));
        assert_eq!(VersionSkew::between(4, 5), Some(VersionSkew::PeerOlder));
        assert_eq!(VersionSkew::between(5, 5), None);
    }

    #[test]
    fn the_recorded_skew_is_reported_with_its_connection() {
        let mut links = LinkReachability::default();
        links.link_up(DEVICE, Some(Carrier::Direct), 0);
        assert_eq!(links.version_skew(DEVICE), None);
        links.mark_incompatible(DEVICE, 0, VersionSkew::PeerOlder);
        assert_eq!(links.version_skew(DEVICE), Some(VersionSkew::PeerOlder));
    }
}
