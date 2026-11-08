//! The per-peer link cache: the one current connection to each peer, and
//! who may be waiting for it.
//!
//! ```text
//!   outbound dial ──┐
//!                   ├──► current link of the peer ──► every `link_to` caller
//!   accepted link ──┘          (generation bump wakes waiters)
//! ```
//!
//! The dial is not the only way a link to a peer comes to exist: an
//! authorized peer's own connection can be accepted while this device's dial
//! is still pending (an address not yet known, a peer not yet listening). A
//! caller must not wait out that dial's deadline for a connection that is
//! already up, so the dial is raced against the accepted link and no lock is
//! held across it.
//!
//! * Per peer: at most one live current link, and at most one dialling
//!   caller (the leader); other callers wait on the slot's change signal.
//! * The signal is a `watch`: a waiter subscribes before it reads the state,
//!   so a change between the read and the wait is never lost.
//! * An accepted link becomes current only when there is no live current
//!   link; it never replaces one that is serving lanes. A second live link
//!   (an accepted one, or a dial that finishes after a current link exists)
//!   is kept as the single standby and takes over when the current one dies.
//!   It is not closed as "redundant": the peer may be using it as its own
//!   current link. A standby it replaces is retired: kept open for a grace
//!   period (long enough for the peer to move to its own current), then
//!   closed; at most `MAX_RETIRED` are kept, the oldest closed first.
//! * Crossed dials: when the live current and standby links are one dialled
//!   here and one accepted, both sides keep the one dialled by the lower
//!   endpoint id (bytes compare), which each side can tell without any
//!   message. Both make it current; the higher-id side closes the other after
//!   a grace period, unless the preferred link has died by then (the other
//!   stays, and is promoted). The lower-id side never closes anything.
//! * Authorization is the caller's: only links already held by the
//!   endpoint's open-connection registry (admitted, revocable) are offered,
//!   and a dialled link is held before it is cached, exactly as before.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use yadorilink_sync_substrate::{PeerId, PeerLink};

#[derive(Default)]
struct SlotState {
    current: Option<Arc<PeerLink>>,
    /// An accepted link that arrived while `current` was live: the next
    /// current one if `current` goes, so a connection the peer opened is
    /// never left served but unselectable.
    standby: Option<Arc<PeerLink>>,
    /// Links a newer standby replaced, each closed by its own timer after the
    /// grace period. Bounded by `MAX_RETIRED`.
    retired: Vec<Retired>,
    /// A caller is dialling for this peer.
    dialing: bool,
    /// Which dial `dialing` speaks of; a dial that was superseded must not clear the flag of
    /// the one that replaced it.
    dial_gen: u64,
    /// The dial whose caller was answered by an accepted link and went away, leaving the dial
    /// to finish alone (see `link_to`). It still counts as dialling, and a caller that finds no
    /// live link waits for it (so no second dial starts beside it), until the network changes:
    /// see [`LinkCache::supersede_detached_dials`].
    detached: Option<tokio::task::AbortHandle>,
}

/// How long a replaced standby stays open: the peer may be using it as ITS
/// current link, and needs time to move to another.
const RETIRE_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// The most replaced links kept at once; past it the oldest is closed.
const MAX_RETIRED: usize = 4;

struct Retired {
    link: Arc<PeerLink>,
    timer: tokio::task::JoinHandle<()>,
}

impl Drop for Retired {
    fn drop(&mut self) {
        self.timer.abort();
    }
}

struct Slot {
    /// This device's endpoint id: with the peer's, it says whose dial wins a crossing.
    local: PeerId,
    /// Test-only: ends every retired link's grace period at once.
    #[cfg(test)]
    expire_now: watch::Sender<bool>,
    grace: std::sync::atomic::AtomicU64,
    state: Mutex<SlotState>,
    changed: watch::Sender<()>,
}

impl Slot {
    fn new(local: PeerId) -> Self {
        Self {
            local,
            state: Mutex::new(SlotState::default()),
            changed: watch::channel(()).0,
            #[cfg(test)]
            expire_now: watch::channel(false).0,
            grace: std::sync::atomic::AtomicU64::new(RETIRE_GRACE.as_millis() as u64),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Keeps `link` as the standby. The standby it replaces is not closed at
    /// once: after simultaneous dials it can be the connection the peer uses
    /// as its current link. It is retired -- closed after the grace period,
    /// or earlier if more than `MAX_RETIRED` pile up -- so a connection that
    /// is served (and kept alive by the transport) cannot accumulate.
    fn set_standby(self: &Arc<Self>, state: &mut SlotState, link: Arc<PeerLink>) {
        if let Some(old) = state.standby.replace(link) {
            self.retire(state, old);
        }
    }

    /// Resolves crossed dials: if `current` and `standby` are live and one was dialled here and
    /// the other accepted, the one dialled by the lower endpoint id becomes current, and the
    /// higher-id side schedules the close of the other.
    fn settle_crossing(self: &Arc<Self>, state: &mut SlotState, peer: PeerId) {
        let (Some(current), Some(standby)) = (state.current.clone(), state.standby.clone()) else {
            return;
        };
        let usable = |l: &Arc<PeerLink>| l.is_alive() && l.peer() == peer;
        if !usable(&current)
            || !usable(&standby)
            || current.dialled_here() == standby.dialled_here()
        {
            return;
        }
        let ours_wins = self.local < peer;
        if standby.dialled_here() == ours_wins {
            std::mem::swap(&mut state.current, &mut state.standby);
        }
        if ours_wins {
            return;
        }
        let loser = state.standby.clone().expect("the loser is the standby");
        let grace =
            std::time::Duration::from_millis(self.grace.load(std::sync::atomic::Ordering::Relaxed));
        let slot = Arc::downgrade(self);
        #[cfg(test)]
        let mut expire_now = self.expire_now.subscribe();
        tokio::spawn(async move {
            let mut path = loser.carrier_changes();
            #[cfg(test)]
            let expired = async {
                let _ = expire_now.wait_for(|now| *now).await;
            };
            #[cfg(not(test))]
            let expired = std::future::pending::<()>();
            tokio::select! {
                () = tokio::time::sleep(grace) => {}
                () = expired => {}
                () = async { while path.next().await.is_some() {} } => return,
            }
            let Some(slot) = slot.upgrade() else { return };
            let mut state = slot.state();
            // Closed only while the preferred link is still up and current; otherwise the
            // loser is the peer's remaining connection and stays.
            let preferred_up = state
                .current
                .as_ref()
                .is_some_and(|c| c.is_alive() && c.connection_id() != loser.connection_id());
            if preferred_up {
                if state
                    .standby
                    .as_ref()
                    .is_some_and(|s| s.connection_id() == loser.connection_id())
                {
                    state.standby = None;
                }
                loser.close();
            }
        });
    }

    fn retire(self: &Arc<Self>, state: &mut SlotState, link: Arc<PeerLink>) {
        state.retired.retain(|r| r.link.is_alive());
        while state.retired.len() >= MAX_RETIRED {
            state.retired.remove(0).link.close();
        }
        let grace =
            std::time::Duration::from_millis(self.grace.load(std::sync::atomic::Ordering::Relaxed));
        let (closing, slot) = (link.clone(), Arc::downgrade(self));
        #[cfg(test)]
        let mut expire_now = self.expire_now.subscribe();
        let timer = tokio::spawn(async move {
            // Over when the grace period is, or when the link closes first
            // (a revocation, the peer): either way the entry goes with it.
            let mut path = closing.carrier_changes();
            #[cfg(test)]
            let expired = async {
                let _ = expire_now.wait_for(|now| *now).await;
            };
            #[cfg(not(test))]
            let expired = std::future::pending::<()>();
            tokio::select! {
                () = tokio::time::sleep(grace) => closing.close(),
                () = expired => closing.close(),
                () = async { while path.next().await.is_some() {} } => {}
            }
            if let Some(slot) = slot.upgrade() {
                slot.state().retired.retain(|r| !Arc::ptr_eq(&r.link, &closing));
            }
        });
        state.retired.push(Retired { link, timer });
    }

    fn notify(&self) {
        self.changed.send_modify(|_| {});
    }

    /// The current link, if it is alive and is `peer`'s; when it is not, a
    /// live standby for `peer` takes its place.
    fn live_current(state: &mut SlotState, peer: PeerId) -> Option<Arc<PeerLink>> {
        let usable = |l: &Arc<PeerLink>| l.is_alive() && l.peer() == peer;
        if state.current.as_ref().is_some_and(usable) {
            return state.current.clone();
        }
        if state.standby.as_ref().is_some_and(usable) {
            state.current = state.standby.take();
            return state.current.clone();
        }
        None
    }

    /// Resolves once a live link to `peer` is current.
    async fn next_current(&self, peer: PeerId) -> Arc<PeerLink> {
        // Subscribed before the state is read: a change after the read is
        // still seen as one by `changed()`.
        let mut changes = self.changed.subscribe();
        loop {
            if let Some(link) = Self::live_current(&mut self.state(), peer) {
                return link;
            }
            // The sender lives in this slot, so it cannot be closed here.
            if changes.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Ends the leader's turn however its future ends, cancellation included.
struct Leading(Arc<Slot>, u64);

impl Drop for Leading {
    fn drop(&mut self) {
        {
            let mut state = self.0.state();
            // A superseded dial leaves the flag to its successor.
            if state.dial_gen == self.1 {
                state.dialing = false;
                state.detached = None;
            }
        }
        self.0.notify();
    }
}

pub(super) struct LinkCache {
    local: PeerId,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    /// The device id of every authorized peer whose connection to this device was just accepted.
    /// A peer that opens a new connection has just been reachable from where it is, which says
    /// something about the connections made to it earlier.
    inbound: tokio::sync::broadcast::Sender<String>,
}

impl LinkCache {
    pub(super) fn new(local: PeerId) -> Self {
        Self { local, slots: Mutex::default(), inbound: tokio::sync::broadcast::channel(16).0 }
    }

    /// Aborts every dial that was left to finish alone, and returns how many. Called when the
    /// network came back: such a dial was started on the network that is gone, can take its
    /// whole handshake deadline (about 33 s) to fail there, and holds the slot's dial turn
    /// meanwhile, so the next caller would queue behind it. Aborting frees the turn; a
    /// connection the peer accepted from it meanwhile is dropped, which is the peer's
    /// connection to lose when the network that carried it is gone.
    pub(super) fn supersede_detached_dials(&self) -> usize {
        let slots: Vec<Arc<Slot>> =
            self.slots.lock().unwrap_or_else(|p| p.into_inner()).values().cloned().collect();
        let mut aborted = 0;
        for slot in slots {
            let detached = slot.state().detached.take();
            if let Some(dial) = detached {
                dial.abort();
                aborted += 1;
            }
        }
        aborted
    }

    /// A receiver of the device ids of peers that just opened a connection to this device.
    pub(super) fn subscribe_inbound(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.inbound.subscribe()
    }

    fn slot(&self, device_id: &str) -> Arc<Slot> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(device_id.to_string())
            .or_insert_with(|| Arc::new(Slot::new(self.local)))
            .clone()
    }

    /// Drops (and closes) whatever is cached for a device the netmap no
    /// longer pins.
    fn forget(&self, slot: &Slot) {
        let mut state = slot.state();
        for stale in [state.current.take(), state.standby.take()].into_iter().flatten() {
            stale.close();
        }
        for retired in std::mem::take(&mut state.retired) {
            retired.link.close();
        }
    }

    /// A live link to `device_id` if there is one, promoting the standby when the current link
    /// is gone. Never dials.
    pub(super) fn live_link(&self, device_id: &str) -> Option<Arc<PeerLink>> {
        let slot = self.slots.lock().unwrap_or_else(|p| p.into_inner()).get(device_id).cloned()?;
        let mut state = slot.state();
        let usable = |l: &Arc<PeerLink>| l.is_alive();
        if state.current.as_ref().is_some_and(usable) {
            return state.current.clone();
        }
        if state.standby.as_ref().is_some_and(usable) {
            state.current = state.standby.take();
            return state.current.clone();
        }
        None
    }

    /// Test-only: every live link held to `device_id`, current and standby.
    #[cfg(test)]
    pub(in crate::peer_connectivity_runtime) fn live_links_for_tests(
        &self,
        device_id: &str,
    ) -> Vec<Arc<PeerLink>> {
        let slot = self.slot(device_id);
        let state = slot.state();
        [state.current.clone(), state.standby.clone()]
            .into_iter()
            .flatten()
            .filter(|l| l.is_alive())
            .collect()
    }

    /// Closes and forgets every link held to `device_id` (a peer that stopped answering); the
    /// next caller dials afresh.
    pub(super) fn drop_links(&self, device_id: &str) {
        let slot = self.slot(device_id);
        self.forget(&slot);
        slot.notify();
    }

    /// Test-only: the grace period of every retired link ends now.
    #[cfg(test)]
    pub(super) fn expire_retired_for_tests(&self, device_id: &str) {
        self.slot(device_id).expire_now.send_replace(true);
    }

    /// Test-only: how many retired links are still held for this device.
    #[cfg(test)]
    pub(super) fn retired_count_for_tests(&self, device_id: &str) -> usize {
        self.slot(device_id).state().retired.len()
    }

    /// An authorized peer's accepted `link`: it becomes `device_id`'s current
    /// link unless a live one is already serving, and wakes everyone waiting
    /// for one.
    pub(super) fn offer_accepted(&self, device_id: &str, link: &PeerLink) {
        let slot = self.slot(device_id);
        {
            let mut state = slot.state();
            // A connection that closed while it waited in the accept queue is not news of the
            // peer, and must not make anything else replace a healthy connection.
            if !link.is_alive() {
                return;
            }
            let link = Arc::new(link.clone());
            let peer = link.peer();
            if Slot::live_current(&mut state, link.peer()).is_some() {
                slot.set_standby(&mut state, link);
                slot.settle_crossing(&mut state, peer);
            } else {
                state.current = Some(link);
            }
        }
        slot.notify();
        // No receiver is not an error: nobody is waiting to hear of it.
        let _ = self.inbound.send(device_id.to_string());
    }

    /// The path kind the link the next lane open would use is on, when that link has one selected.
    /// Read, not promoted: a standby only stands in for a current link that is gone.
    pub(super) fn current_carrier(
        &self,
        device_id: &str,
    ) -> Option<yadorilink_sync_substrate::Carrier> {
        let slot = self.slots.lock().unwrap_or_else(|p| p.into_inner()).get(device_id).cloned()?;
        let state = slot.state();
        let usable = |l: &&Arc<PeerLink>| l.is_alive();
        state.current.as_ref().filter(usable).or(state.standby.as_ref().filter(usable))?.carrier()
    }

    /// Resolves when a live link to `peer` is current for `device_id`
    /// (immediately if there is one): a link the peer opened while this
    /// side's dials were failing.
    pub(super) async fn wait_for_link(&self, device_id: &str, peer: PeerId) -> Arc<PeerLink> {
        self.slot(device_id).next_current(peer).await
    }

    /// The connection to `device_id`: the current live one, else the result
    /// of `dial` -- or an authorized link the peer opens first, whichever is
    /// there first. `peer_of` resolves the device's pinned identity;
    /// `hold` registers a dialled link for revocation and says whether its
    /// peer is still admitted.
    pub(super) async fn link_to<E, Fut>(
        &self,
        device_id: &str,
        peer_of: impl Fn() -> Option<PeerId> + Send + Sync + 'static,
        hold: impl Fn(&PeerLink) -> bool + Send + 'static,
        adopt: impl Fn(&PeerLink) + Send + 'static,
        dial: impl FnOnce(PeerId) -> Fut,
    ) -> Result<Option<Arc<PeerLink>>, E>
    where
        Fut: Future<Output = Result<PeerLink, E>> + Send + 'static,
        E: Send + 'static,
    {
        let slot = self.slot(device_id);
        let peer_of = Arc::new(peer_of);
        let mut parts = Some((hold, adopt, dial));
        loop {
            let mut changes = slot.changed.subscribe();
            // Who the device is, asked before the cache: a cached connection
            // to a device the netmap no longer pins is not one to hand out,
            // however alive it looks.
            let Some(peer) = peer_of() else {
                self.forget(&slot);
                return Ok(None);
            };
            let leading = {
                let mut state = slot.state();
                if let Some(link) = Slot::live_current(&mut state, peer) {
                    return Ok(Some(link));
                }
                // Closed, not just dropped: the connection is also held by
                // whatever serves its streams.
                for stale in [state.current.take(), state.standby.take()].into_iter().flatten() {
                    stale.close();
                }
                if state.dialing {
                    None
                } else {
                    state.dialing = true;
                    state.dial_gen += 1;
                    Some(state.dial_gen)
                }
            };
            let Some(generation) = leading else {
                // Someone else is dialling; wake on any change and look again.
                let _ = changes.changed().await;
                continue;
            };
            let (hold, adopt, dial) = parts.take().expect("a leader returns, so it leads once");
            let dialled = dial(peer);

            // The dial runs as its own task, so that a link the peer opens
            // first does not cancel it: a connection cancelled mid-handshake
            // can already be established at the peer, which may be using it
            // as ITS current link. It finishes on its own and its link
            // becomes the standby. Only the caller going away aborts it.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let task = {
                let (slot, peer_of) = (slot.clone(), peer_of.clone());
                // The dial's turn ends when the dial does (finished, failed
                // or aborted), not when the caller does: a detached dial
                // still counts, so nobody starts a second one beside it.
                let turn = Leading(slot.clone(), generation);
                tokio::spawn(async move {
                    let _turn = turn;
                    let outcome = match dialled.await {
                        Err(error) => Err(error),
                        Ok(link) => Ok(finish_dial(&slot, peer, link, &hold, &adopt, &*peer_of)),
                    };
                    let _ = done_tx.send(outcome);
                })
            };
            let mut dial_task = DialTask(Some(task));
            let mut done_rx = done_rx;
            // Biased: a finished dial is handled before a link that arrived
            // in the same instant.
            return tokio::select! {
                biased;
                done = &mut done_rx => match done {
                    Ok(Ok(outcome)) => Ok(outcome),
                    Ok(Err(error)) => {
                        // A dial that failed as the peer's own link came up
                        // has not failed the call.
                        let current = Slot::live_current(&mut slot.state(), peer);
                        match current {
                            Some(current) if peer_of() == Some(peer) => Ok(Some(current)),
                            _ => Err(error),
                        }
                    }
                    // The task was aborted or panicked.
                    Err(_) => Ok(None),
                },
                link = slot.next_current(peer) => {
                    dial_task.detach(&slot, generation);
                    // An accepted link is made current after the endpoint
                    // held it, but the device can be withdrawn after that and
                    // before the revocation sweep reaches the link: the pin
                    // is read again, as a cache hit reads it.
                    if peer_of() == Some(peer) { Ok(Some(link)) } else { Ok(None) }
                }
            };
        }
    }
}

/// Aborts the dial when the caller goes away, unless it was detached.
struct DialTask(Option<tokio::task::JoinHandle<()>>);

impl DialTask {
    /// Lets the dial finish on its own, and records that nobody waits for it.
    fn detach(&mut self, slot: &Slot, generation: u64) {
        if let Some(task) = self.0.take() {
            let mut state = slot.state();
            if state.dial_gen == generation {
                state.detached = Some(task.abort_handle());
            }
        }
    }
}

impl Drop for DialTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// A finished dial's link: held (admitted, revocable), adopted, and cached --
/// as the current link if there is none, else as the standby. Returns the
/// link the call is answered with.
fn finish_dial(
    slot: &Arc<Slot>,
    peer: PeerId,
    link: PeerLink,
    hold: &impl Fn(&PeerLink) -> bool,
    adopt: &impl Fn(&PeerLink),
    peer_of: &impl Fn() -> Option<PeerId>,
) -> Option<Arc<PeerLink>> {
    // A revocation can land while the dial is in flight. Held first and
    // checked second, so either the revocation finds it or this check sees
    // the withdrawn key.
    if !hold(&link) {
        return None;
    }
    adopt(&link);
    let link = Arc::new(link);
    let answer = {
        let mut state = slot.state();
        if let Some(current) = Slot::live_current(&mut state, peer) {
            // The peer's own link got here first. This one is not closed: the
            // peer may be using it as ITS current link (both sides dial at
            // once), and closing it would take that connection away from it.
            slot.set_standby(&mut state, link);
            slot.settle_crossing(&mut state, peer);
            // The answer is whatever is current after the crossing is settled.
            state.current.clone().unwrap_or(current)
        } else {
            state.current = Some(link.clone());
            link
        }
    };
    slot.notify();
    if peer_of() == Some(peer) {
        Some(answer)
    } else {
        None
    }
}
