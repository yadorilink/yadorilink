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

/// mDNS that runs only while something needs it.
///
/// An mDNS source is a multicast listener: on a busy LAN it wakes the daemon several times a
/// second with other hosts' traffic, which was about half of an idle pair's wakeups. A peer is
/// only looked for when something asks (`resolve`: a dial that needs an address), and just
/// after start, when everything is. So the source is built fast ([`FAST_CADENCE`]) and stays
/// for [`FAST_WINDOW`] after start and after every `resolve`; once that has passed with
/// nobody asking it is dropped, responder included, and the daemon leaves the multicast
/// group. The next `resolve` builds it again, fast, and hands it the last published addresses.
///
/// While it is off this device does not answer queries. A peer that restarts finds this one
/// when this one redials it (the lost connection makes the next dial ask), and a new device is
/// looked for the same way, so two idle devices find each other as soon as either needs the
/// other; the other directories and relays are unaffected.
pub(crate) struct Cadenced<L> {
    inner: Arc<CadencedInner<L>>,
    swapper: tokio::task::JoinHandle<()>,
}

struct CadencedInner<L> {
    factory: Box<dyn Fn(std::time::Duration) -> Option<L> + Send + Sync>,
    state: std::sync::Mutex<CadenceState<L>>,
    /// Wakes the idle task when the source was started again.
    started: tokio::sync::Notify,
}

struct CadenceState<L> {
    /// `None` while off, and when this host could not build one.
    source: Option<Arc<L>>,
    published: Option<EndpointData>,
    fast_until: tokio::time::Instant,
}

/// Query cadence while something is looking for a peer, and just after start.
pub(crate) const FAST_CADENCE: std::time::Duration = std::time::Duration::from_millis(1500);
/// How long the source runs after start and after a `resolve`.
pub(crate) const FAST_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

impl<L: AddressLookup> Cadenced<L> {
    /// `factory` builds the source, or `None` when this host cannot run it. Must be called inside
    /// a tokio runtime.
    pub(crate) fn new(
        factory: impl Fn(std::time::Duration) -> Option<L> + Send + Sync + 'static,
    ) -> Self {
        let source = factory(FAST_CADENCE).map(Arc::new);
        let inner = Arc::new(CadencedInner {
            factory: Box::new(factory),
            state: std::sync::Mutex::new(CadenceState {
                source,
                published: None,
                fast_until: tokio::time::Instant::now() + FAST_WINDOW,
            }),
            started: tokio::sync::Notify::new(),
        });
        let weak = Arc::downgrade(&inner);
        // Sleeps until the moment the window ends, and while the source is off, until it is
        // started again: no periodic check.
        let swapper = tokio::spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else { return };
                let deadline = {
                    let state = inner.state();
                    state.source.is_some().then_some(state.fast_until)
                };
                match deadline {
                    Some(deadline) => {
                        tokio::time::sleep_until(deadline).await;
                        inner.stop_if_idle();
                    }
                    None => inner.started.notified().await,
                }
            }
        });
        Self { inner, swapper }
    }
}

impl<L> Cadenced<L> {
    fn has_source(&self) -> bool {
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner()).source.is_some()
    }
}

impl<L> Drop for Cadenced<L> {
    fn drop(&mut self) {
        self.swapper.abort();
    }
}

impl<L: AddressLookup> CadencedInner<L> {
    fn state(&self) -> std::sync::MutexGuard<'_, CadenceState<L>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Drops the source once nothing has asked for a whole [`FAST_WINDOW`].
    fn stop_if_idle(&self) {
        let mut state = self.state();
        if state.source.is_some() && tokio::time::Instant::now() >= state.fast_until {
            state.source = None;
        }
    }

    /// Builds the source again after it was dropped; if it cannot be built it stays off.
    fn start(&self, state: &mut CadenceState<L>) {
        let Some(source) = (self.factory)(FAST_CADENCE).map(Arc::new) else { return };
        if let Some(published) = &state.published {
            source.publish(published);
        }
        state.source = Some(source);
        self.started.notify_one();
    }
}

impl<L> std::fmt::Debug for Cadenced<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cadenced")
    }
}

impl<L: AddressLookup> AddressLookup for Cadenced<L> {
    fn publish(&self, data: &EndpointData) {
        let mut state = self.inner.state();
        state.published = Some(data.clone());
        if let Some(source) = &state.source {
            source.publish(data);
        }
    }

    fn resolve(&self, endpoint_id: iroh::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let source = {
            let mut state = self.inner.state();
            state.fast_until = tokio::time::Instant::now() + FAST_WINDOW;
            if state.source.is_none() {
                self.inner.start(&mut state);
            }
            state.source.clone()?
        };
        source.resolve(endpoint_id)
    }
}

/// One mDNS source running on a runtime of its own.
///
/// swarm-discovery stops only its guardian task when its guard is dropped; the tasks behind
/// it keep running, about 60 wakeups per second for each dropped source. A source that is
/// replaced at run time ([`Cadenced`]) must therefore not share the daemon's runtime: every
/// task it starts, in either library, is spawned on this one, and dropping the source shuts the
/// runtime down, which ends all of them whatever the libraries do on drop.
pub(crate) struct IsolatedMdns {
    source: iroh_mdns_address_lookup::MdnsAddressLookup,
    runtime: Option<tokio::runtime::Runtime>,
}

impl IsolatedMdns {
    fn build(
        local: iroh::EndpointId,
        cadence: std::time::Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("mdns")
            .enable_all()
            .build()?;
        let source = {
            // The library spawns its tasks on the runtime that is current while it is built.
            let _entered = runtime.enter();
            iroh_mdns_address_lookup::MdnsAddressLookup::builder()
                .service_name(SERVICE_NAME)
                .discovery_cadence(cadence)
                .build(local)?
        };
        Ok(Self { source, runtime: Some(runtime) })
    }

    #[cfg(test)]
    fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.runtime.as_ref().expect("runs until dropped").handle().clone()
    }
}

impl Drop for IsolatedMdns {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // Does not wait for tasks and is allowed inside an async context.
            runtime.shutdown_background();
        }
    }
}

impl std::fmt::Debug for IsolatedMdns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IsolatedMdns")
    }
}

impl AddressLookup for IsolatedMdns {
    fn publish(&self, data: &EndpointData) {
        self.source.publish(data);
    }

    fn resolve(&self, endpoint_id: iroh::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        self.source.resolve(endpoint_id)
    }
}

/// The mDNS source for the endpoint `local`, or `None` when this host's
/// network cannot run it. See [`Cadenced`] for the query cadence.
///
/// Not being able to use the LAN is not a reason to refuse to start: every
/// other path to a peer is unaffected, so this degrades to "no LAN lookup"
/// and says so.
pub(crate) fn mdns(local: iroh::EndpointId) -> Option<Cadenced<IsolatedMdns>> {
    let first = std::sync::atomic::AtomicBool::new(true);
    let cadenced = Cadenced::new(move |cadence| match IsolatedMdns::build(local, cadence) {
        Ok(mdns) => Some(mdns),
        Err(err) => {
            // Said once at start; a later rebuild failing keeps the old source.
            if first.swap(false, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(%err, "local-network peer lookup unavailable on this host");
            }
            None
        }
    });
    cadenced.has_source().then_some(cadenced)
}

#[cfg(test)]
mod tests;
