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

use std::collections::HashMap;
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
}

impl PeerRegistry {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            removals: tokio::sync::watch::channel(()).0,
            registrations: tokio::sync::watch::channel(()).0,
        }
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
