//! One `PeerSyncSession` per peer that is authorized and reachable over the
//! iroh substrate.
//!
//! ```text
//!   pinned in PeerAuthorityState ──┐
//!                                  ├──► session registered in DaemonState.peers
//!   live iroh connection to it   ──┘        (lanes served, hydration and
//!                                            repair candidate, convergence
//!                                            executor beside it)
//! ```
//!
//! A session is what every peer-facing consumer looks up: inbound block and
//! service streams are served by it, hydration and repair draw their content
//! sources from it, and the convergence executor that closes a projection
//! obligation sits beside it. Everything such a session sends or receives
//! rides the iroh lanes (`SyncStack::transports_for`), so whether one exists
//! is decided here from exactly two facts:
//!
//! * the peer is authorized: `PeerAuthorityState` pins its signing key, the
//!   same predicate transport admission uses. What it may read or write is
//!   still decided per group on every request; this only decides whether
//!   there is anything to ask.
//! * the substrate can reach it: this device's endpoint holds a live
//!   connection to it. The session lives as long as that connection and is
//!   opened again, with backoff, when a new one can be made.
//!
//! Losing either ends the session. A device the netmap withdraws loses its
//! key (the per-peer keeper is stopped and removes its session) and its
//! connections (closed by `PeerConnectivityRuntime::revoke_device`, which
//! ends the keeper's wait on its own). Dropping the peer session driver --
//! how a device stops answering peers -- stops every keeper, and each one
//! removes the session it registered.
//!
//! The legacy QUIC transport decides none of this and exchanges nothing
//! with a session.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use yadorilink_peer_session::peer_session::PeerSyncSession;

use crate::daemon_state::{DaemonState, PeerAuthorityState};
use crate::supervise::BackoffConfig;
use crate::sync_adapter::sync_stack::SyncStack;

/// A connection that stayed up this long was a working one: the next
/// reconnect starts from the shortest backoff again rather than the one the
/// last failures had escalated to.
const HEALTHY_CONNECTION: Duration = Duration::from_secs(3);

/// Keeps one session per authorized, reachable peer for as long as it runs.
///
/// Aborting the returned task stops every per-peer keeper, and each keeper
/// removes the session it registered as it stops -- so the holder of this
/// handle (the peer session driver) decides how long sessions over its
/// endpoint can exist.
pub(crate) fn keep_peer_sessions(
    state: &Arc<DaemonState>,
    stack: &Arc<SyncStack>,
) -> tokio::task::JoinHandle<()> {
    let changes = state.authority.subscribe_to_peer_changes();
    tokio::spawn(follow_authorized_peers(Arc::downgrade(state), Arc::downgrade(stack), changes))
}

/// One keeper per pinned peer, started and stopped as the pinned set
/// changes. A keeper whose peer's key changed is replaced, so a session is
/// never kept over a connection authenticated as someone the netmap no
/// longer names.
async fn follow_authorized_peers(
    state: Weak<DaemonState>,
    stack: Weak<SyncStack>,
    mut changes: tokio::sync::watch::Receiver<()>,
) {
    let mut keepers = Keepers::default();
    loop {
        let Some(pinned) = state.upgrade().map(|state| state.authority.pinned_peers()) else {
            return;
        };
        let pinned: HashMap<String, [u8; 32]> = pinned.into_iter().collect();
        keepers.0.retain(|device, (key, keeper)| {
            let keep = pinned.get(device) == Some(key) && !keeper.is_finished();
            if !keep {
                keeper.abort();
            }
            keep
        });
        // A native connection authenticated as a key the netmap replaced goes
        // whether or not a successor keeper already registered its session.
        if let Some(state) = state.upgrade() {
            state.native_replication.detach_unpinned(&pinned);
        }
        for (device, key) in pinned {
            if let std::collections::hash_map::Entry::Vacant(slot) = keepers.0.entry(device) {
                let device = slot.key().clone();
                let keeper = tokio::spawn(keep_session(state.clone(), stack.clone(), device));
                slot.insert((key, keeper));
            }
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

/// The per-peer keepers, stopped together when their owner is.
#[derive(Default)]
struct Keepers(HashMap<String, ([u8; 32], tokio::task::JoinHandle<()>)>);

impl Drop for Keepers {
    fn drop(&mut self) {
        for (_, keeper) in self.0.values() {
            keeper.abort();
        }
    }
}

/// Connects to `device`, holds a session for it while the connection lives,
/// and reconnects with backoff when it ends -- until stopped.
async fn keep_session(state: Weak<DaemonState>, stack: Weak<SyncStack>, device: String) {
    let mut registered =
        Registered { state: state.clone(), device: device.clone(), session: None, native: None };
    let mut attempt: u32 = 0;
    loop {
        let started = tokio::time::Instant::now();
        let link = {
            let Some(stack) = stack.upgrade() else { return };
            stack.link_to(&device).await.map(|link| (link, stack))
        };
        match link {
            Ok((link, linked_stack)) => {
                let Some(mut removals) =
                    state.upgrade().map(|state| state.peers.subscribe_to_removals())
                else {
                    return;
                };
                registered.session = open_session(&state, &linked_stack, &device);
                if registered.session.is_some() {
                    registered.native =
                        Some(start_native_replication(&state, &linked_stack, &device));
                }
                // Followed through a handle that does not keep the connection
                // open: the endpoint's link cache owns it, and a revocation or
                // the peer going away must be able to end it.
                let mut carrier = link.carrier_changes();
                drop((link, linked_stack));
                // Another session for this peer may still be registered --
                // typically the one a keeper this one replaced has not let go
                // of yet. Open ours once it is gone, for as long as the
                // connection lasts, rather than holding a connection with no
                // session on it.
                let mut connected = true;
                while connected && registered.session.is_none() {
                    tokio::select! {
                        removed = removals.changed() => if removed.is_err() { return },
                        path = carrier.next() => connected = path.is_some(),
                    }
                    if connected {
                        let Some(stack) = stack.upgrade() else { return };
                        registered.session = open_session(&state, &stack, &device);
                        if registered.session.is_some() {
                            registered.native =
                                Some(start_native_replication(&state, &stack, &device));
                        }
                    }
                }
                if connected {
                    while carrier.next().await.is_some() {}
                }
                registered.release();
            }
            Err(error) => {
                tracing::debug!(peer = %device, %error, "no iroh connection to this peer yet");
            }
        }
        if started.elapsed() > HEALTHY_CONNECTION {
            attempt = 0;
        }
        // The backoff is for a peer that cannot be reached. One that opened
        // a connection to this device meanwhile (its dial can succeed while
        // ours was refused or timed out) can be, so that ends the wait.
        let Some(waiting) = stack.upgrade() else { return };
        let backoff = BackoffConfig::RECONNECT.next(attempt);
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            () = waiting.endpoint().wait_for_link(&device) => {}
        }
        drop(waiting);
        attempt = attempt.saturating_add(1);
    }
}

/// Keeps native replication with `device` up beside its sync session: the
/// dialing side keeps a connection dialled, the other accepts. Ends with the
/// session, and is aborted when the keeper lets go of it.
fn start_native_replication(
    state: &Weak<DaemonState>,
    stack: &Arc<SyncStack>,
    device: &str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(crate::native_replication_runtime::keep_dialed(
        state.clone(),
        stack.clone(),
        device.to_string(),
    ))
}

/// The session a keeper registered, removed when the keeper lets go of it
/// or is stopped -- and only if it is still the registered one, so a keeper
/// never removes a session somebody else put there.
struct Registered {
    state: Weak<DaemonState>,
    device: String,
    session: Option<Arc<PeerSyncSession>>,
    /// The task keeping native replication dialled beside `session`.
    native: Option<tokio::task::JoinHandle<()>>,
}

impl Registered {
    fn release(&mut self) {
        if let Some(native) = self.native.take() {
            native.abort();
        }
        if let (Some(session), Some(state)) = (self.session.take(), self.state.upgrade()) {
            state.peers.remove_if_current(&self.device, &session);
            // Only when nobody has registered a session since: a successor's
            // native connection is its own, and an old one dies with its
            // carrier.
            if !state.peers.has_session(&self.device) {
                state.native_replication.detach(&self.device);
            }
        }
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.release();
    }
}

/// The groups a session for `device` may serve right now: what the netmap
/// authorizes, less any group whose policy this device currently distrusts.
fn servable_groups(authority: &PeerAuthorityState, device: &str) -> Vec<String> {
    let mut groups: Vec<String> = authority
        .authorized_groups_for_peer(device)
        .into_iter()
        .filter(|group| !authority.is_group_policy_stale(group))
        .collect();
    groups.sort();
    groups
}

/// Builds and registers `device`'s session over `stack`'s lanes, or
/// returns `None` when a session is already registered for it (one built
/// elsewhere stands) or the device is no longer pinned.
fn open_session(
    state: &Weak<DaemonState>,
    stack: &Arc<SyncStack>,
    device: &str,
) -> Option<Arc<PeerSyncSession>> {
    let state = state.upgrade()?;
    if state.peers.has_session(device) {
        return None;
    }
    let groups = servable_groups(&state.authority, device);
    let sync_roots = crate::peer_orchestrator::sync_roots_for_groups(&state, &groups);
    let store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        state.device_id.clone(),
        device.to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        store,
        groups,
        stack.transports_for(device),
        crate::peer_orchestrator::peer_sync_session_deps(&state),
    );
    if !state.register_peer_session_if_absent(device, session.clone(), sync_roots) {
        return None;
    }
    // Read again now that the session is visible. A netmap update or a
    // policy revocation that ran between the first read and registration
    // looked for a session to update and found none; this is what brings
    // the session up to date with it. One that runs after this point finds
    // the session and updates it itself.
    session.set_authorized_groups(servable_groups(&state.authority, device));
    if yadorilink_fs_platform::join_timeline::is_active() {
        for group in servable_groups(&state.authority, device) {
            yadorilink_fs_platform::join_timeline::mark_with_peer(
                &state.device_id,
                &group,
                yadorilink_fs_platform::join_timeline::Milestone::PeerSyncSessionRegistered,
                device,
            );
        }
    }
    // A first session for this peer: its groups just went from none to its servable set.
    state.native_replication.wake_reconcile();
    if state.authority.peer_signing_key(device).is_none() {
        state.peers.remove_if_current(device, &session);
        return None;
    }
    // The same event also makes custody confirmable: ask the peer now rather
    // than at the next periodic sweep (the backstop).
    state.request_custody_refresh(&servable_groups(&state.authority, device));
    Some(session)
}

#[cfg(test)]
mod inbound_tests;
#[cfg(test)]
mod tests;
