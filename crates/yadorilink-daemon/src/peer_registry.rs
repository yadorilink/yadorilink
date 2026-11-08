//! Owns this device's running sync sessions
//! (`device_id -> Arc<PeerSyncSession>`). The map is private -- every caller
//! reaches it through this type's own methods, never a raw
//! `MutexGuard`/`HashMap` crossing the module boundary.
//!
//! A peer's reachability is not kept here. It is the vocabulary below
//! ([`PeerReachability`]), and its only producer is the iroh connectivity
//! runtime (`PeerConnectivityRuntime::reachability`): whether a session is
//! registered here says nothing about whether the peer can be reached. `peer_orchestrator.rs`'s own doc comments
//! encode exact ordering guarantees around session teardown/revocation
//! against this same data; the methods here preserve those guarantees
//! exactly (same lock scopes, same removal semantics) rather than
//! reshaping them.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use yadorilink_peer_session::peer_session::PeerSyncSession;

/// Why a peer could not be connected. Rendered by the CLI and desktop app
/// as the reason a peer "cannot connect", and mapped verbatim onto the
/// control socket's peer-status wire fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableCategory {
    /// No candidate address to try at all (no endpoints learned).
    NoCandidates,
    /// Candidates were probed but stayed silent — most often a symmetric
    /// NAT or CGNAT pair that cannot be traversed.
    NoResponse,
    /// No datagram could get out at all (even local/STUN probes failed).
    UdpBlocked,
    /// The peer answered but refused the handshake — a key or
    /// authorization mismatch, distinct from being unreachable on the
    /// network.
    HandshakeRefused,
    /// The account replaced this device with another one (start over): it is refused, not
    /// merely out of reach, and nothing will change that.
    DeviceReplaced,
}

impl UnreachableCategory {
    /// Stable wire/status slug.
    pub fn as_str(self) -> &'static str {
        match self {
            UnreachableCategory::NoCandidates => "no_candidates",
            UnreachableCategory::NoResponse => "no_response",
            UnreachableCategory::UdpBlocked => "udp_blocked",
            UnreachableCategory::HandshakeRefused => "handshake_refused",
            UnreachableCategory::DeviceReplaced => "device_replaced",
        }
    }
}

/// A peer's live connectivity as reported to the CLI and desktop app: being
/// connected, connected (directly, or through a relay server), or not
/// reachable (with the reason). See `crate::route`'s own doc comment for the
/// `Durability != Connectivity` invariant this extends without weakening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// Candidate paths are still being raced; not yet connected, but not
    /// yet given up on either.
    Connecting,
    /// A path to the peer is confirmed and in use -- see `RouteKind` for
    /// which kind.
    Connected(crate::route::RouteKind),
    /// The peer cannot currently be reached; carries why.
    Unreachable(UnreachableCategory),
}

impl PeerReachability {
    pub fn is_connected(self) -> bool {
        matches!(self, Self::Connected(_))
    }

    /// Stable wire/status slug: "connecting" | "connected" | "unreachable".
    /// Deliberately does NOT distinguish `RouteKind` -- unchanged from
    /// before this pass, so no existing wire/CLI consumer's output shifts;
    /// see `route_str` for that.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected(_) => "connected",
            Self::Unreachable(_) => "unreachable",
        }
    }
}

/// One peer's live runtime: the session, and the convergence executor
/// that runs the local half of its work.
///
/// One entry, not two parallel maps. Two maps make "a session with no
/// executor" and "an executor outlived its session" representable, and
/// registration and teardown can interleave into exactly those states --
/// a cleanup for the session it is replacing removing the executor a
/// newly registered session just installed. Keeping them in one value
/// under one mutex makes both states unconstructible.
#[derive(Clone)]
pub struct PeerRuntime {
    pub session: Arc<PeerSyncSession>,
    /// The executor's work is local, and it lives in this crate, so it is
    /// held beside the session rather than inside it. One per session,
    /// which is exactly what each session used to construct for itself.
    pub convergence: Arc<crate::local_convergence::LocalConvergenceExecutor>,
}

pub struct PeerRegistry {
    /// device_id -> the running sync session and its executor, so local
    /// changes can be broadcast and sessions torn down on ACL revocation.
    sessions: Mutex<HashMap<String, PeerRuntime>>,
    /// Marked each time a session leaves the registry, so a caller waiting
    /// for a slot to free up can wait for that instead of polling.
    removals: tokio::sync::watch::Sender<()>,
    /// Marked each time a session joins the registry, so an inbound stream
    /// that beat its session here can wait for it instead of being dropped.
    registrations: tokio::sync::watch::Sender<()>,
    /// Marked when something a person is waiting for needed a peer and no session was there:
    /// the keepers of peers that share the wanted folder dial at once.
    demand: Arc<DemandHub>,
}

/// What the demand channel says: for each folder, the number of the last wake that named it.
/// Cumulative, so a keeper that was busy when a wake came still sees it, however many wakes
/// followed.
#[derive(Debug, Default)]
pub(crate) struct Demand {
    seq: u64,
    wanted: HashMap<String, u64>,
}

/// One keeper's view of the demand channel.
pub(crate) struct DemandWatch {
    rx: tokio::sync::watch::Receiver<Arc<Demand>>,
    /// The wake number up to which this keeper has acted or has been told it need not.
    seen: u64,
}

impl DemandWatch {
    /// What was wanted so far is not news: the dial or connection about to be made answers it.
    pub(crate) fn acknowledge(&mut self) {
        self.seen = self.rx.borrow_and_update().seq;
    }

    /// Completes when a folder in `groups()` was wanted after the last acknowledgement. A wake
    /// for other folders is no reason to dial this peer, and the dial would also wake LAN
    /// discovery. Does not complete while the channel is closed.
    pub(crate) async fn wanted(&mut self, groups: impl Fn() -> Option<Vec<String>>) {
        loop {
            let newly = {
                let demand = self.rx.borrow_and_update();
                let newly = groups().is_some_and(|groups| {
                    groups
                        .iter()
                        .any(|group| demand.wanted.get(group).is_some_and(|n| *n > self.seen))
                });
                newly.then_some(demand.seq)
            };
            if let Some(seq) = newly {
                self.seen = seq;
                return;
            }
            if self.rx.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

/// The demand channel and its rate limit. A demand inside the window is held and sent when the
/// window ends, so the last person to ask is not lost. Every decision is taken under the gate.
struct DemandHub {
    wake: tokio::sync::watch::Sender<Arc<Demand>>,
    gate: Mutex<DemandGate>,
}

#[derive(Default)]
struct DemandGate {
    seq: u64,
    wanted: HashMap<String, u64>,
    /// When the last wake was sent.
    last: Option<tokio::time::Instant>,
    /// Folders asked for since then.
    pending: HashSet<String>,
    /// The task that will send `pending` when the window ends, if one is scheduled: a task that
    /// finds another number here was overtaken and does nothing.
    flush: Option<u64>,
    flushes: u64,
}

/// How many wakes back a keeper can still see what was wanted: at least five minutes.
const DEMAND_HISTORY_WAKES: u64 = 64;

/// The shortest time between two demand wakes of the keepers.
const DEMAND_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

impl DemandHub {
    /// Sends what is pending, now. The caller holds the gate.
    fn send(&self, gate: &mut DemandGate) {
        gate.flush = None;
        if gate.pending.is_empty() {
            return;
        }
        gate.last = Some(tokio::time::Instant::now());
        gate.seq += 1;
        let seq = gate.seq;
        for group in std::mem::take(&mut gate.pending) {
            gate.wanted.insert(group, seq);
        }
        // A keeper looks back over the wakes of a dial, minutes at most; older entries (and
        // folders that no longer exist) are of no use to anyone.
        gate.wanted.retain(|_, n| *n + DEMAND_HISTORY_WAKES > seq);
        self.wake.send_replace(Arc::new(Demand { seq, wanted: gate.wanted.clone() }));
    }
}

impl PeerRegistry {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            removals: tokio::sync::watch::channel(()).0,
            registrations: tokio::sync::watch::channel(()).0,
            demand: Arc::new(DemandHub {
                wake: tokio::sync::watch::channel(Arc::new(Demand::default())).0,
                gate: Mutex::new(DemandGate::default()),
            }),
        }
    }

    /// Something a person is waiting for in `group_id` found no session to fetch from: wakes the
    /// keepers of peers that share that folder and are waiting out a backoff or a slow dial, so
    /// they dial now. At most one wake per [`DEMAND_INTERVAL`]; a demand inside the window is
    /// sent when it ends, with the folders asked for meanwhile.
    pub(crate) fn demand_connections(&self, group_id: &str) {
        let hub = &self.demand;
        let mut gate = hub.gate.lock().unwrap_or_else(|p| p.into_inner());
        gate.pending.insert(group_id.to_owned());
        let now = tokio::time::Instant::now();
        let window_ends = gate.last.map(|at| at + DEMAND_INTERVAL).filter(|end| *end > now);
        let (Some(end), Ok(runtime)) = (window_ends, tokio::runtime::Handle::try_current()) else {
            // The window is over, or there is no runtime to wait on (and then no keeper to wake
            // later): send now. A flush scheduled meanwhile is overtaken.
            hub.send(&mut gate);
            return;
        };
        if gate.flush.is_some() {
            return;
        }
        gate.flushes += 1;
        let ticket = gate.flushes;
        gate.flush = Some(ticket);
        drop(gate);
        let hub = Arc::clone(hub);
        runtime.spawn(async move {
            tokio::time::sleep_until(end).await;
            let mut gate = hub.gate.lock().unwrap_or_else(|p| p.into_inner());
            if gate.flush == Some(ticket) {
                hub.send(&mut gate);
            }
        });
    }

    pub(crate) fn subscribe_to_demand(&self) -> DemandWatch {
        let mut rx = self.demand.wake.subscribe();
        let seen = rx.borrow_and_update().seq;
        DemandWatch { rx, seen }
    }

    /// Wakes after any session is removed from here from now on. Subscribe
    /// before looking at the registry, so a removal between the look and
    /// the wait is not missed.
    pub(crate) fn subscribe_to_registrations(&self) -> tokio::sync::watch::Receiver<()> {
        self.registrations.subscribe()
    }

    pub(crate) fn subscribe_to_removals(&self) -> tokio::sync::watch::Receiver<()> {
        self.removals.subscribe()
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, PeerRuntime>> {
        self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether `device_id` is known to speak this build's versions. A peer whose lane hello or
    /// service RPC was of another version is reachable but not compatible, so nothing that
    /// depends on its answers (custody, handoff, durability) may count it. A peer with no
    /// version trouble on record is compatible: a stale answer cannot come from a peer that
    /// answers nothing, and an unanswered question is already "not confirmed".
    pub fn peer_is_version_compatible(
        &self,
        connectivity: &crate::peer_connectivity_runtime::PeerConnectivityRuntime,
        device_id: &str,
    ) -> bool {
        !connectivity.is_version_incompatible(device_id)
            && self.session(device_id).is_none_or(|session| !session.rpc_version_mismatch())
    }

    /// The live session for `device_id`, if any.
    pub fn session(&self, device_id: &str) -> Option<Arc<PeerSyncSession>> {
        self.lock_sessions().get(device_id).map(|runtime| runtime.session.clone())
    }

    /// The local-convergence executor registered beside `device_id`'s
    /// session, for a caller that needs the local half rather than the wire
    /// half of that peer's runtime.
    pub fn convergence(
        &self,
        device_id: &str,
    ) -> Option<Arc<crate::local_convergence::LocalConvergenceExecutor>> {
        self.lock_sessions().get(device_id).map(|runtime| runtime.convergence.clone())
    }

    /// Whether a session is currently registered for `device_id`.
    pub fn has_session(&self, device_id: &str) -> bool {
        self.lock_sessions().contains_key(device_id)
    }

    /// Every live session that shares `group_id`, sorted by device id (the
    /// deterministic order the materialization-repair candidate loop
    /// requires).
    pub fn sessions_for_group(&self, group_id: &str) -> Vec<(String, Arc<PeerSyncSession>)> {
        let sessions = self.lock_sessions();
        let mut candidates: Vec<_> = sessions
            .iter()
            .filter(|(_, runtime)| runtime.session.shares_group(group_id))
            .map(|(peer_id, runtime)| (peer_id.clone(), runtime.session.clone()))
            .collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates
    }

    /// Every live session, device id paired with its `Arc`.
    pub fn all_sessions(&self) -> Vec<(String, Arc<PeerSyncSession>)> {
        self.lock_sessions()
            .iter()
            .map(|(id, runtime)| (id.clone(), runtime.session.clone()))
            .collect()
    }

    /// Installs `session` as the current session for `device_id`,
    /// returning whatever session (if any) it replaced.
    pub fn register_session(
        &self,
        device_id: String,
        session: Arc<PeerSyncSession>,
        convergence: Arc<crate::local_convergence::LocalConvergenceExecutor>,
    ) -> Option<Arc<PeerSyncSession>> {
        let previous = self
            .lock_sessions()
            .insert(device_id, PeerRuntime { session, convergence })
            .map(|previous| previous.session);
        self.registrations.send_replace(());
        previous
    }

    /// Installs `session` for `device_id` only if no session is registered
    /// for it, returning whether it was installed.
    pub fn register_session_if_absent(
        &self,
        device_id: &str,
        session: Arc<PeerSyncSession>,
        convergence: Arc<crate::local_convergence::LocalConvergenceExecutor>,
    ) -> bool {
        let installed = match self.lock_sessions().entry(device_id.to_string()) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(PeerRuntime { session, convergence });
                true
            }
        };
        if installed {
            self.registrations.send_replace(());
        }
        installed
    }

    /// `device_id`'s convergence executor, if a session is registered.
    pub fn local_convergence(
        &self,
        device_id: &str,
    ) -> Option<Arc<crate::local_convergence::LocalConvergenceExecutor>> {
        self.lock_sessions().get(device_id).map(|runtime| runtime.convergence.clone())
    }

    /// Every live session that shares `group_id`, paired with its
    /// executor, in the same deterministic order as
    /// [`Self::sessions_for_group`].
    pub fn convergence_for_group(
        &self,
        group_id: &str,
    ) -> Vec<(String, Arc<PeerSyncSession>, Arc<crate::local_convergence::LocalConvergenceExecutor>)>
    {
        // Built from the same locked snapshot as `sessions_for_group`,
        // in the same deterministic order, so a session and its executor
        // can never be observed apart.
        let sessions = self.lock_sessions();
        let mut candidates: Vec<_> = sessions
            .iter()
            .filter(|(_, runtime)| runtime.session.shares_group(group_id))
            .map(|(peer_id, runtime)| {
                (peer_id.clone(), runtime.session.clone(), runtime.convergence.clone())
            })
            .collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates
    }

    /// Removes `device_id`'s session unconditionally, whatever it is --
    /// used for forced teardown/revocation paths that must clear the slot
    /// regardless of which session (if any) currently occupies it.
    pub fn remove(&self, device_id: &str) -> Option<Arc<PeerSyncSession>> {
        let removed = self.lock_sessions().remove(device_id).map(|runtime| runtime.session);
        if removed.is_some() {
            self.removals.send_replace(());
        }
        removed
    }

    /// Removes `device_id`'s session only if it is still exactly `expected`
    /// (identity via `Arc::ptr_eq`), so a task ending an old session can
    /// never delete a newer session a fresher connection has since
    /// installed. Returns whether a removal happened.
    pub fn remove_if_current(&self, device_id: &str, expected: &Arc<PeerSyncSession>) -> bool {
        let mut sessions = self.lock_sessions();
        let matches =
            sessions.get(device_id).is_some_and(|current| Arc::ptr_eq(&current.session, expected));
        if matches {
            sessions.remove(device_id);
            drop(sessions);
            self.removals.send_replace(());
        }
        matches
    }
}

#[cfg(test)]
mod demand_tests {
    use std::time::Duration;

    use super::*;

    fn all(groups: &[&str]) -> impl Fn() -> Option<Vec<String>> {
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        move || Some(groups.clone())
    }

    async fn is_ready(watch: &mut DemandWatch, groups: &[&str]) -> bool {
        // Polled once, without letting paused time move on.
        tokio::time::timeout(Duration::ZERO, watch.wanted(all(groups))).await.is_ok()
    }

    /// The first demand wakes at once and names its folder; nobody asking wakes nobody.
    #[tokio::test(start_paused = true)]
    async fn the_first_demand_wakes_at_once_with_its_folder() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        assert!(!is_ready(&mut watch, &["g1"]).await);
        peers.demand_connections("g1");
        assert!(is_ready(&mut watch, &["g1"]).await);
        assert!(!is_ready(&mut watch, &["g1"]).await, "acted on: not news again");
    }

    /// A demand inside the window is not lost: it is sent when the window ends, together with
    /// every folder asked for meanwhile, and as one wake.
    #[tokio::test(start_paused = true)]
    async fn a_demand_inside_the_window_is_sent_when_it_ends() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        let mut other = peers.subscribe_to_demand();
        peers.demand_connections("g1");
        watch.acknowledge();
        other.acknowledge();

        tokio::time::advance(Duration::from_secs(2)).await;
        peers.demand_connections("g2");
        peers.demand_connections("g3");
        peers.demand_connections("g2");
        tokio::task::yield_now().await;
        assert!(!is_ready(&mut watch, &["g2", "g3"]).await, "inside the window nothing is sent");

        tokio::time::advance(DEMAND_INTERVAL - Duration::from_secs(2) - Duration::from_millis(5))
            .await;
        tokio::task::yield_now().await;
        assert!(!is_ready(&mut watch, &["g2", "g3"]).await, "a few milliseconds early");

        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        assert!(is_ready(&mut watch, &["g3"]).await, "the window ended");
        assert!(is_ready(&mut other, &["g2"]).await, "the one wake named both folders");
        assert!(!is_ready(&mut watch, &["g1"]).await, "g1 was acknowledged");

        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert!(!is_ready(&mut watch, &["g2", "g3"]).await, "one deferred wake, not a stream");
    }

    /// The deferred wake starts a window of its own.
    #[tokio::test(start_paused = true)]
    async fn a_deferred_wake_opens_the_next_window() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        peers.demand_connections("g1");
        peers.demand_connections("g2");
        tokio::time::advance(DEMAND_INTERVAL + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        watch.acknowledge();

        peers.demand_connections("g3");
        tokio::task::yield_now().await;
        assert!(!is_ready(&mut watch, &["g3"]).await, "the window of the deferred wake is open");
        tokio::time::advance(DEMAND_INTERVAL + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(is_ready(&mut watch, &["g3"]).await);
    }

    /// A relevant wake followed by an unrelated one, while the keeper was busy, is still seen.
    #[tokio::test(start_paused = true)]
    async fn a_relevant_wake_survives_a_later_unrelated_one() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        peers.demand_connections("mine");
        tokio::time::advance(DEMAND_INTERVAL + Duration::from_millis(1)).await;
        peers.demand_connections("other");
        tokio::task::yield_now().await;
        assert!(is_ready(&mut watch, &["mine"]).await);
    }

    /// A flush scheduled before a send that overtook it does not fire early for a later demand.
    #[tokio::test(start_paused = true)]
    async fn an_overtaken_flush_does_not_send_a_later_demand_early() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        peers.demand_connections("g1");
        watch.acknowledge();
        tokio::time::advance(Duration::from_secs(1)).await;
        peers.demand_connections("g2"); // schedules a flush for t = 5 s
        tokio::time::advance(DEMAND_INTERVAL - Duration::from_secs(1)).await;
        // The window just ended; this send overtakes the scheduled flush.
        peers.demand_connections("g3");
        tokio::task::yield_now().await;
        assert!(is_ready(&mut watch, &["g2", "g3"]).await, "sent at once, the window being over");
        watch.acknowledge();
        // A new demand now is inside a fresh window; the old flush task must not send it.
        peers.demand_connections("g4");
        tokio::time::advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        assert!(!is_ready(&mut watch, &["g4"]).await, "held until its own window ends");
        tokio::time::advance(DEMAND_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(is_ready(&mut watch, &["g4"]).await);
    }

    /// What was wanted long ago is forgotten, so folders that come and go do not pile up.
    #[tokio::test(start_paused = true)]
    async fn old_demands_are_forgotten() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        for n in 0..(DEMAND_HISTORY_WAKES * 2) {
            peers.demand_connections(&format!("folder-{n}"));
            tokio::time::advance(DEMAND_INTERVAL + Duration::from_millis(1)).await;
        }
        let kept = peers.demand.gate.lock().unwrap().wanted.len() as u64;
        assert!(kept <= DEMAND_HISTORY_WAKES, "kept {kept}");
        assert!(is_ready(&mut watch, &["folder-0", "folder-127"]).await, "the recent ones stay");
        watch.acknowledge();
        assert!(!is_ready(&mut watch, &["folder-0"]).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_concerns_only_the_peers_of_its_folders() {
        let peers = PeerRegistry::new();
        let mut watch = peers.subscribe_to_demand();
        peers.demand_connections("g1");
        assert!(!is_ready(&mut watch, &["g0", "g2"]).await);
        assert!(!is_ready(&mut watch, &[]).await);
        assert!(is_ready(&mut watch, &["g0", "g1"]).await);
    }
}
