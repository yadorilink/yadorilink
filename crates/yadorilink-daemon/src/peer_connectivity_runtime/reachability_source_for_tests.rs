//! The one place a test makes a peer's connection state change the way the
//! running daemon would, without dialling anything.
//!
//! Each function feeds the connectivity runtime exactly the reports the iroh
//! endpoint gives it at that moment of a connection's life -- a dial starting
//! or failing, a connection coming up over a path, a connection closing --
//! through the same entry points the endpoint's observer and connection
//! followers call. A test driven through here therefore sees what production
//! derives from those reports, never a hand-assembled reachability value.
//!
//! Tests that pin what `yadorilink status`, the health count and fetch
//! availability MEAN for a peer go through this module rather than writing a
//! reachability directly, so they keep asserting the same meaning whatever
//! feeds it.

use yadorilink_sync_substrate::{Carrier, PeerId};

use crate::daemon_state::DaemonState;
use crate::peer_registry::{PeerReachability, UnreachableCategory};
use crate::route::RouteKind;

/// The endpoint a dial to `peer_device_id` is made to. Any fixed key per
/// device does: the runtime matches a dial's end to its start by it and
/// checks nothing else.
fn endpoint_of(peer_device_id: &str) -> PeerId {
    let mut key = [0u8; 32];
    for (slot, byte) in key.iter_mut().zip(peer_device_id.bytes()) {
        *slot = byte;
    }
    PeerId::from_bytes(key)
}

/// A connection attempt to `peer_device_id` has started and has not yet
/// succeeded or given up.
pub fn dialing(state: &DaemonState, peer_device_id: &str) {
    state.peer_connectivity.record_dial_started(peer_device_id, endpoint_of(peer_device_id));
}

/// A connection to `peer_device_id` is up with a direct path selected.
pub fn connected_directly(state: &DaemonState, peer_device_id: &str) {
    state.peer_connectivity.record_link_up(peer_device_id, Some(Carrier::Direct));
}

/// A connection to `peer_device_id` is up, and the only path it has is
/// through a relay server.
pub fn relay_only(state: &DaemonState, peer_device_id: &str) {
    state.peer_connectivity.record_link_up(peer_device_id, Some(Carrier::Relay));
}

/// The connection to `peer_device_id` carried a lane hello of another protocol version: the
/// device is reachable and cannot sync. Needs a connection to be up, as in production.
pub fn version_incompatible(state: &DaemonState, peer_device_id: &str) {
    state.peer_connectivity.record_version_incompatible(peer_device_id);
}

/// Every path to `peer_device_id` was tried and none answered: whatever
/// connection there was is gone, and the dial that followed failed for `why`.
pub fn failed(state: &DaemonState, peer_device_id: &str, why: UnreachableCategory) {
    ended(state, peer_device_id);
    let endpoint = endpoint_of(peer_device_id);
    state.peer_connectivity.record_dial_started(peer_device_id, endpoint);
    state.peer_connectivity.record_dial_failed(endpoint, why);
}

/// The connection to `peer_device_id` ended (it dropped, or the peer went
/// away) and nothing replaced it.
pub fn ended(state: &DaemonState, peer_device_id: &str) {
    let open = state.peer_connectivity.links().open_links(peer_device_id);
    for link in open {
        state.peer_connectivity.record_link_closed(peer_device_id, link);
    }
}

/// Puts `peer_device_id` into `reachability` by the reports that produce it,
/// for a test that is about something else and only needs the peer in that
/// state.
pub fn reach(state: &DaemonState, peer_device_id: &str, reachability: PeerReachability) {
    match reachability {
        PeerReachability::Connecting => dialing(state, peer_device_id),
        PeerReachability::Connected(RouteKind::Direct) => connected_directly(state, peer_device_id),
        PeerReachability::Connected(RouteKind::Relay) => relay_only(state, peer_device_id),
        PeerReachability::Unreachable(why) => failed(state, peer_device_id, why),
    }
}
