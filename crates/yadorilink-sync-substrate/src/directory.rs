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

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::peer::PeerId;

/// A stream of "what the directory knows of a peer changed" signals.
pub type ChangeStream = n0_future::boxed::BoxStream<()>;

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

    /// A signal that fires each time what this directory knows of `peer` changes.
    ///
    /// iroh asks a lookup for a peer's addresses once, while it has no
    /// selected path to that peer, and keeps what that stream yields from then
    /// on. An answer that only exists later (the peer's relay, published after
    /// both devices connected over the LAN) would otherwise never reach it.
    /// `None` means this directory has no such signal.
    fn changes(&self, _peer: PeerId) -> Option<ChangeStream> {
        None
    }
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
    /// The public (NAT-mapped) addresses of this endpoint, as last published. See
    /// [`without_hairpin`].
    own_public: Arc<Mutex<HashSet<IpAddr>>>,
    /// Whether a resolve for a peer the directory knows nothing of yet stays open for
    /// later records instead of reporting nothing. Only meaningful where another lookup
    /// (LAN discovery) already keeps the dial waiting for addresses.
    wait_for_records: bool,
    /// How long a lookup that has not yet seen a relay for the peer stays open for one.
    live_window: std::time::Duration,
}

/// How long a lookup waits for a relay record that has not arrived yet.
///
/// iroh asks for a peer's addresses once and does not ask again for as long as that lookup is
/// open, and LAN discovery's own lookup is part of the same one, so a stream that never ended
/// would also keep the next LAN lookup from ever starting. Long enough for the coordination
/// plane to publish the peer's relay after both devices came up together; short enough that an
/// unknown peer is looked for on the LAN again soon.
const LIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `url` is a relay URL a lookup can hand to iroh.
pub fn is_usable_relay_url(url: &str) -> bool {
    url.parse::<iroh::RelayUrl>().is_ok()
}

impl DirectoryLookup {
    pub(crate) fn new(directory: Arc<dyn AddressDirectory>, local: PeerId) -> Self {
        Self {
            directory,
            local,
            own_public: Arc::default(),
            wait_for_records: false,
            live_window: LIVE_WINDOW,
        }
    }

    pub(crate) fn waiting_for_records(mut self, wait: bool) -> Self {
        self.wait_for_records = wait;
        self
    }

    #[cfg(test)]
    fn with_live_window(mut self, window: std::time::Duration) -> Self {
        self.live_window = window;
        self
    }
}

/// What the directory knows of `endpoint_id` now, as an iroh lookup item.
fn item_for(
    directory: &dyn AddressDirectory,
    own_public: &Mutex<HashSet<IpAddr>>,
    endpoint_id: iroh::EndpointId,
) -> Option<iroh::address_lookup::Item> {
    let (direct, relays) = directory.resolve(PeerId::from_bytes(*endpoint_id.as_bytes()))?;
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
    let own_public = own_public.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let direct = without_hairpin(direct, !usable_relays.is_empty(), &own_public);
    if direct.is_empty() && usable_relays.is_empty() {
        return None;
    }
    let mut info = iroh::address_lookup::EndpointInfo::new(endpoint_id).with_ip_addrs(direct);
    for url in usable_relays {
        info = info.with_relay_url(url);
    }
    Some(iroh::address_lookup::Item::new(info, PROVENANCE, None))
}

/// Whether `ip` is an address other networks can reach (not private, loopback or link-local).
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Drops the peer's candidates that sit on this endpoint's own public IP, when another way to the
/// peer remains (a private address, which on the same network is the LAN, or a relay).
///
/// Two devices behind one router both show the router's public address. A packet to the other's
/// "public" address has to turn around inside the router (NAT hairpin), and many routers do it
/// for one direction or intermittently. Worse, the device that is dialed answers on the path the
/// packet came in on, so a handshake that arrives through the hairpin is answered into it and
/// never completes, while the relay that would have carried the answer goes unused. Without the
/// candidate, the dial goes over the LAN or the relay, both of which work in both directions.
pub(crate) fn without_hairpin(
    direct: Vec<SocketAddr>,
    has_relay: bool,
    own_public: &HashSet<IpAddr>,
) -> Vec<SocketAddr> {
    let hairpin = |a: &SocketAddr| own_public.contains(&a.ip());
    let other_way = has_relay || direct.iter().any(|a| !hairpin(a) && !is_public(a.ip()));
    if !other_way {
        return direct;
    }
    direct.into_iter().filter(|a| !hairpin(a)).collect()
}

impl iroh::address_lookup::AddressLookup for DirectoryLookup {
    fn publish(&self, data: &iroh::address_lookup::EndpointData) {
        let direct: Vec<SocketAddr> = data.ip_addrs().copied().collect();
        let relays: Vec<String> = data.relay_urls().map(ToString::to_string).collect();
        *self.own_public.lock().unwrap_or_else(|p| p.into_inner()) =
            direct.iter().map(SocketAddr::ip).filter(|ip| is_public(*ip)).collect();
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
        let peer = PeerId::from_bytes(*endpoint_id.as_bytes());
        // Subscribed before the directory is read: a record that lands in between is then seen
        // on the stream instead of falling between the snapshot and the subscription.
        let updates = self.directory.changes(peer);
        let initial = item_for(self.directory.as_ref(), &self.own_public, endpoint_id);
        match (initial, updates) {
            (None, None) => None,
            (Some(item), None) => Some(Box::pin(n0_future::stream::once(Ok(item)))),
            (None, Some(_)) if !self.wait_for_records => None,
            // Already complete: nothing more to wait for.
            (Some(item), Some(_)) if has_relay(&item) => {
                Some(Box::pin(n0_future::stream::once(Ok(item))))
            }
            (first, Some(updates)) => {
                let live = Live {
                    first,
                    updates,
                    directory: self.directory.clone(),
                    own_public: self.own_public.clone(),
                    endpoint_id,
                    deadline: Box::pin(tokio::time::sleep(self.live_window)),
                    done: false,
                };
                Some(Box::pin(n0_future::stream::unfold(live, Live::next)))
            }
        }
    }
}

fn has_relay(item: &iroh::address_lookup::Item) -> bool {
    item.endpoint_info().relay_urls().next().is_some()
}

/// A lookup held open for the relay of a peer that has none recorded yet.
struct Live {
    first: Option<iroh::address_lookup::Item>,
    updates: ChangeStream,
    directory: Arc<dyn AddressDirectory>,
    own_public: Arc<Mutex<HashSet<IpAddr>>>,
    endpoint_id: iroh::EndpointId,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
    done: bool,
}

impl Live {
    /// The next item: what was known when the lookup started, then each change, until one carries
    /// a relay, the window ends, or the directory stops signalling.
    async fn next(
        mut self,
    ) -> Option<(Result<iroh::address_lookup::Item, iroh::address_lookup::Error>, Self)> {
        use n0_future::StreamExt as _;

        if self.done {
            return None;
        }
        if let Some(item) = self.first.take() {
            self.done = has_relay(&item);
            return Some((Ok(item), self));
        }
        loop {
            tokio::select! {
                () = &mut self.deadline => return None,
                change = self.updates.next() => {
                    change?;
                    let item = item_for(self.directory.as_ref(), &self.own_public, self.endpoint_id);
                    if let Some(item) = item {
                        self.done = has_relay(&item);
                        return Some((Ok(item), self));
                    }
                }
            }
        }
    }
}

/// Names this lookup in iroh's own logs and metrics.
const PROVENANCE: &str = "yadori-coordination";

#[cfg(test)]
mod tests;
