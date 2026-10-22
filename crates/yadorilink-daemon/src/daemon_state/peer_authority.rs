//! Owns this device's view of which peers are authorized for what: every
//! peer's netmap-derived signing key, writer authorization and full-replica
//! status, the generation counter that versions them, the coordination
//! plane's pinned service key, and each group's verified policy state and
//! stale marker.
//!
//! Every field is private; callers reach them only through this type's own
//! methods. Mutators return whether anything changed and never call out
//! while holding a lock -- the notifications a change triggers
//! (reconciliation wakes, substrate projection, session revocation) are the
//! caller's job, done after the mutation has released its guard. See
//! `DaemonState::replace_peer_netmap_metadata` and friends for those
//! wrappers. Every mutator whose wrapper adds such a notification
//! (`record_peer_signing_key`, `replace_peer_netmap_metadata`,
//! `set_peer_group_writer`, `mark_group_policy_stale`,
//! `apply_policy_snapshot`) is `pub(super)`, so
//! nothing outside `daemon_state` can apply the change without it.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use yadorilink_sync_sqlite::OfflinePeerAuthorization;

use super::offline_authorization::{
    self, AuthorizationProvenance, OfflineAuthorizationCache, SnapshotMirror,
};
use super::{now_unix, GroupPolicyResolution};
use crate::change_policy::GroupPolicyState;

#[derive(Default)]
struct PeerNetmapMetadata {
    signing_keys: HashMap<String, [u8; 32]>,
    writers: HashSet<(String, String)>,
    full_replicas: HashSet<(String, String)>,
}

/// Every group's verified policy state and stale marker, kept under ONE lock
/// so a policy snapshot switches both at once: no reader can observe a group
/// that the snapshot verified as still stale-but-unverified, or a group the
/// snapshot failed as neither stale nor dropped from the trusted set.
#[derive(Default)]
struct GroupPolicyBook {
    /// group_id -> current signed policy-log head coordinates from the latest
    /// coordination netmap full update. Used to verify a change's signed
    /// auth_seq/auth_epoch/policy_head_hash stamp after its signature verifies.
    verified: HashMap<String, GroupPolicyState>,
    /// group_id -> unix time its most recent policy snapshot FAILED
    /// verification. A group listed here is untrusted: its verified state has
    /// been dropped and change admission for it fails closed until a valid
    /// snapshot clears the mark, so a revoke a corrupt snapshot hid can never
    /// leave a revoked writer admitted. Presence is the stale flag; the value
    /// is the failure time for diagnostics.
    stale: HashMap<String, i64>,
}

#[derive(Default)]
pub struct PeerAuthorityState {
    /// The coordination plane's currently-pinned service signing key --
    /// the SAME trust anchor `change_policy::verify_group_policy_log` uses
    /// for group policy logs, mirrored here (from the identical pin
    /// decision `record_group_policy_states` already makes on every
    /// netmap update). `None` until the first netmap update with policy
    /// distribution enabled has been processed.
    pinned_coordination_service_key: Mutex<Option<[u8; 32]>>,
    /// One atomic view of every peer's netmap-derived signing key, writer
    /// authorization, and full-replica status. Keeping these under one lock
    /// prevents change admission and last-replica custody from observing a
    /// partially-applied revocation/demotion snapshot.
    peer_netmap_metadata: Mutex<PeerNetmapMetadata>,
    /// Monotonic counter bumped on every actual change to the netmap-derived
    /// authorization state above (`PeerNetmapMetadata::writers` /
    /// `PeerNetmapMetadata::full_replicas`). A version-present confirmation captures it
    /// before the peer round-trip and requires it unchanged after the reply, so
    /// a revoke/demote — or any membership churn — arriving during the wait
    /// fails the confirmation closed rather than trusting a now-stale ACK.
    membership_generation: std::sync::atomic::AtomicU64,
    /// The coordination plane's snapshot generation the persisted
    /// authorization was last written from, read once at startup. 0 when
    /// no netmap has ever written it.
    ///
    /// Not an authorization of anything: it is the cache's provenance, and
    /// the only thing it decides is whether the run's FIRST netmap frame
    /// is allowed to PRUNE. A frame older than the cache it would prune is
    /// an authenticated replay, and deleting rows on its say-so is durable
    /// loss of an authorization the plane never withdrew -- see
    /// `peer_orchestrator::NetmapDiffState::may_withdraw`.
    restored_snapshot_generation: std::sync::atomic::AtomicU64,
    /// Each group's verified policy state and stale marker -- see
    /// [`GroupPolicyBook`].
    group_policies: Mutex<GroupPolicyBook>,
    /// Marked after every change to which peers are pinned or what they are
    /// authorized for, once the change is visible. Carries no data: a
    /// subscriber re-reads the state it cares about, so a change it missed
    /// while busy costs nothing, and several changes collapse into one wake.
    peers_changed: tokio::sync::watch::Sender<()>,
    /// This device's on-disk mirror of the last authorization a live netmap
    /// gave it -- see `offline_authorization`'s module doc for what that
    /// snapshot is (a last-known-good record, kept so an offline restart
    /// can go on talking to peers the plane already authorized) and what it
    /// is not (an authority: it is only ever written from a live netmap
    /// application, and never widens one).
    ///
    /// `None` for a `PeerAuthorityState` with no disk behind it, which
    /// authorizes nobody across a restart because it remembers nothing.
    offline_authorization: Option<OfflineAuthorizationCache>,
    /// Whether the authorization this state currently holds came from a
    /// netmap applied this run or from the on-disk snapshot -- see
    /// [`AuthorizationProvenance`]. State, not a comment, because acting on
    /// last-known-good authorization is a different security position from
    /// acting on the plane's current answer.
    authorization_provenance: Mutex<AuthorizationProvenance>,
    /// Test-only hook run inside `apply_policy_snapshot`'s critical section,
    /// at the point where the pre-atomicity sequence had already cleared the
    /// verified groups' stale markers but not yet swapped the trusted set in.
    #[cfg(test)]
    policy_snapshot_mid_apply_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl PeerAuthorityState {
    /// A state with no disk behind it: it starts empty, remembers nothing
    /// across a restart, and persists nothing. Test-only -- the daemon
    /// always builds through [`restored_from`](Self::restored_from), so
    /// production has no route to an authority that silently forgets its
    /// peers when the process ends.
    #[cfg(test)]
    fn new() -> Self {
        Self::default()
    }

    /// The daemon's own constructor: restores this device's last-known-good
    /// peer authorization from `cache` and keeps the cache to mirror every
    /// later netmap application into.
    ///
    /// What is restored is exactly what a live netmap last authorized, so
    /// this can only ever repeat a decision the coordination plane made and
    /// this device verified -- it never authorizes a peer no netmap named.
    /// The first netmap this run replaces it (see
    /// [`note_live_netmap_authority`](Self::note_live_netmap_authority)),
    /// so the snapshot never outranks the live answer.
    pub(super) fn restored_from(cache: OfflineAuthorizationCache) -> Self {
        let now = now_unix();
        let (restored, expired): (Vec<_>, Vec<_>) = cache.restore().into_iter().partition(|peer| {
            offline_authorization::is_within_offline_horizon(peer.captured_at_unix, now)
        });
        if !expired.is_empty() {
            // Judged, not merely recorded. An authorization this device has
            // had no chance to re-verify for longer than the horizon is one
            // it stops acting on: the whole contract is CONTINUING a recent
            // verified answer, and an answer this old is no longer one.
            // The rows are left where they are -- the next live netmap
            // rewrites them, and deleting them here would turn a read into
            // a write on every start.
            tracing::warn!(
                peer_count = expired.len(),
                horizon_secs = offline_authorization::OFFLINE_AUTHORIZATION_HORIZON_SECS,
                "ignoring peers whose last-known-good authorization is older than this device \
                 will act on offline; they are authorized again only by a live netmap"
            );
        }
        // The version counters are read and seeded whether or not any row
        // survived: the generation must not go backwards across a restart
        // even when every peer was withdrawn, and the plane snapshot
        // generation is what a stale first frame is judged against.
        let versions = cache.snapshot_versions();
        {
            let mut mirrored = cache.write_order();
            mirrored.seed_reserved_generation(versions.membership_generation);
            mirrored.note_snapshot_generation(versions.snapshot_generation);
        }
        let state = Self { offline_authorization: Some(cache), ..Self::default() };
        state
            .restored_snapshot_generation
            .store(versions.snapshot_generation, std::sync::atomic::Ordering::Release);
        state
            .membership_generation
            .store(versions.membership_generation, std::sync::atomic::Ordering::Release);
        if restored.is_empty() {
            return state;
        }
        let mut captured_at_unix = i64::MAX;
        let mut generation = 0u64;
        {
            let mut metadata = state.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
            for peer in &restored {
                captured_at_unix = captured_at_unix.min(peer.captured_at_unix);
                generation = generation.max(peer.membership_generation);
                metadata.signing_keys.insert(peer.device_id.clone(), peer.signing_key);
                for group in &peer.writer_groups {
                    metadata.writers.insert((peer.device_id.clone(), group.clone()));
                }
                for group in &peer.full_replica_groups {
                    // The same intersection the live path applies: a
                    // full-replica bit for a group the peer may not write
                    // is not an authorization of any kind.
                    if peer.writer_groups.contains(group) {
                        metadata.full_replicas.insert((peer.device_id.clone(), group.clone()));
                    }
                }
            }
        }
        // Continue the membership generation the snapshot was taken at
        // rather than restarting it at zero, so a version captured before
        // the restart cannot compare equal to one captured after it.
        //
        // The surviving rows are a floor, not the answer: the row holding
        // the highest generation is exactly the one a withdrawal deletes,
        // and an unchanged row is not rewritten to restate a number. The
        // reserved counter above is what actually carries the guarantee;
        // this only takes the larger of the two, so a row written by some
        // path that did not reserve cannot be undercut either.
        state.membership_generation.fetch_max(generation, std::sync::atomic::Ordering::AcqRel);
        *state.authorization_provenance.lock().unwrap_or_else(|p| p.into_inner()) =
            AuthorizationProvenance::OfflineLastKnownGood {
                peer_count: restored.len(),
                captured_at_unix,
            };
        tracing::info!(
            peer_count = restored.len(),
            captured_at_unix,
            "no netmap yet this run: operating on the last-known-good peer authorization \
             restored from disk. These peers were authorized by the last netmap this device \
             verified; no other peer can be authorized until a live netmap arrives, and the \
             first one that does replaces this entirely."
        );
        state
    }

    /// How many durable snapshot transactions this daemon has issued --
    /// the write cost of the netmap pushes it has applied.
    #[cfg(test)]
    pub(crate) fn offline_snapshot_durable_writes(&self) -> usize {
        self.offline_authorization.as_ref().map_or(0, |cache| cache.durable_writes())
    }

    /// The membership-generation ceiling this run believes it has already
    /// put on disk -- see `OfflineAuthorizationCache::reserved_generation`.
    #[cfg(test)]
    pub(crate) fn offline_snapshot_reserved_generation(&self) -> u64 {
        self.offline_authorization.as_ref().map_or(0, |cache| cache.reserved_generation())
    }

    /// Whether this device is currently acting on the last-known-good
    /// snapshot rather than on a netmap verified this run -- see
    /// [`AuthorizationProvenance`].
    pub fn authorization_provenance(&self) -> AuthorizationProvenance {
        *self.authorization_provenance.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Records that a live netmap has been applied this run, so the
    /// authorization now in force is the coordination plane's current
    /// answer and not the restored snapshot. Called by every netmap-derived
    /// mutator below; the snapshot they also write is from then on that
    /// answer's mirror.
    fn note_live_netmap_authority(&self) {
        let mut provenance =
            self.authorization_provenance.lock().unwrap_or_else(|p| p.into_inner());
        if *provenance != AuthorizationProvenance::LiveNetmap {
            *provenance = AuthorizationProvenance::LiveNetmap;
        }
    }

    /// Mirrors `device_id`'s CURRENT in-memory authorization into the
    /// on-disk snapshot, or withdraws it if the netmap no longer pins a
    /// signing key for it.
    ///
    /// Called after a netmap-derived mutation has released the metadata
    /// guard, never while holding it. The row is read back out of the live
    /// state inside the write-order lock rather than handed in by the
    /// caller, so what reaches disk is always the authorization actually in
    /// force and two concurrent mutations cannot land out of order.
    ///
    /// A peer with no pinned key is withdrawn rather than stored with an
    /// empty key: the key is what a local-network announcement is matched
    /// against, so a keyless row could authorize nothing anyway, and
    /// leaving it would outlive the netmap that removed the device.
    fn persist_peer_authorization(&self, device_id: &str) {
        let Some(cache) = self.offline_authorization.as_ref() else {
            return;
        };
        let mut mirrored = cache.write_order();
        let generation = self.membership_generation();
        let captured_at_unix = now_unix();
        let entry = {
            let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
            metadata.signing_keys.get(device_id).map(|signing_key| {
                let writer_groups: Vec<String> = metadata
                    .writers
                    .iter()
                    .filter(|(peer, _)| peer == device_id)
                    .map(|(_, group)| group.clone())
                    .collect();
                let full_replica_groups: Vec<String> = metadata
                    .full_replicas
                    .iter()
                    .filter(|(peer, _)| peer == device_id)
                    .map(|(_, group)| group.clone())
                    .collect();
                OfflinePeerAuthorization {
                    device_id: device_id.to_string(),
                    signing_key: *signing_key,
                    writer_groups,
                    full_replica_groups,
                    membership_generation: generation,
                    captured_at_unix,
                }
            })
        };
        match entry {
            Some(peer) => cache.store(&mut mirrored, &peer),
            None => cache.forget(&mut mirrored, device_id, generation),
        }
    }

    /// The coordination plane's snapshot generation the persisted
    /// authorization was captured at when this run started -- 0 if none
    /// was ever recorded.
    pub(crate) fn restored_snapshot_generation(&self) -> u64 {
        self.restored_snapshot_generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Records which plane snapshot the rows written from now on belong
    /// to, so a LATER run can tell a frame older than this cache from one
    /// that may prune it. Called once per admitted netmap frame, before
    /// that frame writes anything.
    pub(crate) fn note_applied_snapshot_generation(&self, snapshot_generation: u64) {
        if let Some(cache) = self.offline_authorization.as_ref() {
            cache.write_order().note_snapshot_generation(snapshot_generation);
        }
    }

    /// Drops every persisted authorization for a device `present` does not
    /// name -- the disk half of "a live netmap replaces the snapshot
    /// wholesale".
    ///
    /// The netmap diff already tears down (and thereby un-persists) every
    /// restored peer the snapshot still holds in memory. This is for the
    /// rows that have no in-memory peer to tear down: an authorization too
    /// old for [`is_within_offline_horizon`](offline_authorization::is_within_offline_horizon)
    /// to act on is left on disk at startup rather than rewritten, and
    /// without this it would sit there across every later run. A netmap
    /// that does not name the device is this device's opportunity to learn
    /// that it is gone, and the row goes with it.
    ///
    /// Callers must pass the device set of a FULL authoritative netmap
    /// snapshot. Nothing narrower may prune: pruning on a partial view
    /// would delete authorizations the plane never withdrew.
    pub(super) fn forget_offline_authorizations_absent_from(&self, present: &HashSet<String>) {
        let Some(cache) = self.offline_authorization.as_ref() else {
            return;
        };
        let mut mirrored = cache.write_order();
        let generation = self.membership_generation();
        for peer in cache.restore() {
            if !present.contains(&peer.device_id) {
                tracing::info!(
                    device_id = %peer.device_id,
                    "the first netmap of this run does not name this device; deleting its \
                     last-known-good authorization so no later restart acts on it"
                );
                cache.forget(&mut mirrored, &peer.device_id, generation);
            }
        }
    }

    /// Deletes the whole last-known-good snapshot, in memory and on disk.
    ///
    /// For the events after which this device has no authorization left to
    /// remember: signing out, or no longer being a registered device. A
    /// last-known-good record of who this device's peers were must not
    /// outlive the account relationship that produced it.
    pub(super) fn forget_offline_authorization(&self) {
        // Advanced BEFORE the erasure, not after: the erasure is the
        // write that carries the generation to disk, and a bump made
        // afterwards would be a generation this run reached that no later
        // run could know about. The WAKE still happens at the end, once
        // what a woken subscriber re-reads is the cleared state.
        let generation = self.advance_membership_generation();
        if let Some(cache) = self.offline_authorization.as_ref() {
            let mut mirrored = cache.write_order();
            {
                let mut metadata =
                    self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
                metadata.signing_keys.clear();
                metadata.writers.clear();
                metadata.full_replicas.clear();
            }
            cache.forget_all(&mut mirrored, generation);
        }
        {
            // The verified policy goes too: a device with no account
            // relationship has no group whose policy it should still be
            // acting on, and leaving the trusted set behind would let a
            // group keep admitting changes after this device stopped being
            // a member of anything.
            let mut book = self.group_policies();
            book.verified.clear();
            book.stale.clear();
        }
        *self.authorization_provenance.lock().unwrap_or_else(|p| p.into_inner()) =
            AuthorizationProvenance::Unestablished;
        self.peers_changed.send_replace(());
    }

    /// Records the coordination plane's CURRENTLY pinned
    /// service signing key, mirrored from `record_group_policy_states`'s
    /// own pin decision on every netmap update -- see the field's own
    /// doc comment. A `Mutex`, not a `OnceLock` like `device_static_
    /// secret` above: unlike a device's own identity, the pinned service
    /// key can legitimately be updated (the pin-decision logic itself
    /// governs whether a NEW presented key is accepted as a rotation or
    /// rejected as a mismatch; this setter just mirrors whatever that
    /// logic already decided, it makes no decision of its own).
    pub fn set_pinned_coordination_service_key(&self, key: [u8; 32]) {
        *self.pinned_coordination_service_key.lock().unwrap_or_else(|p| p.into_inner()) = Some(key);
    }

    /// The coordination plane's currently pinned service signing key, if
    /// this device has processed at least one policy-bearing netmap
    /// update. `None` is the fail-safe default: "cannot verify anything"
    /// against this key, never a wildcard accept.
    pub fn pinned_coordination_service_key(&self) -> Option<[u8; 32]> {
        *self.pinned_coordination_service_key.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Mirrors a peer's pinned Ed25519 change-history signing key from the
    /// netmap so the change authenticator can verify that device's changes.
    ///
    /// Only the insert: `DaemonState::record_peer_signing_key` is the entry
    /// point, and it also re-projects the peer's substrate reachability.
    pub(super) fn record_peer_signing_key(&self, device_id: &str, key: [u8; 32]) {
        let changed = self
            .peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .signing_keys
            .insert(device_id.to_string(), key)
            != Some(key);
        self.note_live_netmap_authority();
        self.persist_peer_authorization(device_id);
        if changed {
            self.peers_changed.send_replace(());
        }
    }

    /// Every device whose signing key the netmap currently pins, with that
    /// key. Order is unspecified.
    ///
    /// The set transport admission accepts: a pinned device is one this
    /// device may hold a connection to, whatever groups it is authorized
    /// for right now.
    pub fn pinned_peers(&self) -> Vec<(String, [u8; 32])> {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .signing_keys
            .iter()
            .map(|(device, key)| (device.clone(), *key))
            .collect()
    }

    /// The peers this device currently authorizes, each with the groups it
    /// may write -- the same shape a netmap snapshot has, so the two can be
    /// diffed against each other.
    ///
    /// What the netmap orchestrator starts a run holding: after an offline
    /// restart this is the restored last-known-good snapshot, and diffing
    /// the first live netmap against it is what lets that netmap withdraw a
    /// restored peer it no longer names. A peer pinned with no group at all
    /// is still an entry, because it is still an endpoint this device would
    /// accept a connection from.
    pub fn authorized_peer_snapshot(&self) -> HashMap<String, HashSet<String>> {
        let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let mut snapshot: HashMap<String, HashSet<String>> = metadata
            .signing_keys
            .keys()
            .map(|device_id| (device_id.clone(), HashSet::new()))
            .collect();
        for (device_id, group_id) in &metadata.writers {
            snapshot.entry(device_id.clone()).or_default().insert(group_id.clone());
        }
        snapshot
    }

    /// Wakes once after any change to which peers are pinned or what they
    /// are authorized for. The receiver starts out having seen the current
    /// state, so a subscriber reads that state itself right after
    /// subscribing.
    pub fn subscribe_to_peer_changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.peers_changed.subscribe()
    }

    /// The pinned Ed25519 signing key for `device_id`, if one is known.
    pub fn peer_signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .signing_keys
            .get(device_id)
            .copied()
    }

    /// Reverse lookup for `peer_signing_key`: which pinned device, if any,
    /// this key belongs to. Used to resolve an unauthenticated LAN discovery
    /// announcement's public key back to a device id worth adding a
    /// connection candidate for -- the linear scan is fine at this scale
    /// (bounded by this device's own peer count, not by network traffic).
    ///
    /// Also doubles as local discovery's live authorization predicate
    /// (`.is_some()`) -- deliberately a fresh lookup against current
    /// `peer_netmap_metadata` on every call, not a set snapshotted once,
    /// so discovery started before any peer is known starts working the
    /// moment one is pinned, and correctly stops working the moment one is
    /// revoked, with no explicit refresh needed on the caller's part.
    pub fn device_id_for_signing_key(&self, key: &[u8; 32]) -> Option<String> {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .signing_keys
            .iter()
            .find(|(_, k)| *k == key)
            .map(|(device_id, _)| device_id.clone())
    }

    /// Whether the endpoint with signing key `key` is a peer this device may
    /// act on a local-network announcement for: pinned by the netmap AND
    /// authorized for at least one group, read under one guard so a
    /// revocation cannot be seen half-applied.
    ///
    /// Stricter than `device_id_for_signing_key(..).is_some()`, which is
    /// transport admission: a device pinned but not (or no longer) authorized
    /// for anything is not a reason to go looking for it on the LAN. Anyone on
    /// the LAN can announce any key, so the announcement itself decides
    /// nothing; this does.
    pub fn is_authorized_lan_peer(&self, key: &[u8; 32]) -> bool {
        let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        metadata
            .signing_keys
            .iter()
            .filter(|(_, k)| *k == key)
            .any(|(device_id, _)| metadata.writers.iter().any(|(peer, _)| peer == device_id))
    }

    /// Applies one peer's netmap entry as an authoritative snapshot and
    /// returns whether anything changed. Every peer-scoped authorization set
    /// is replaced, not incrementally patched, so demotion/revocation cannot
    /// leave a stale writer or full-replica bit behind merely because the
    /// transport session was already connected.
    ///
    /// The generation bump happens inside the same critical section as the
    /// mutation, so a reader that captured the generation before a
    /// round-trip can never see the new metadata with the old generation.
    pub(super) fn replace_peer_netmap_metadata(
        &self,
        device_id: &str,
        signing_key: Option<[u8; 32]>,
        authorized_groups: &HashSet<String>,
        full_replica_groups: &HashSet<String>,
        mirror: SnapshotMirror,
    ) -> bool {
        let mut metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let before_writers: HashSet<String> = metadata
            .writers
            .iter()
            .filter(|(peer, _)| peer == device_id)
            .map(|(_, group)| group.clone())
            .collect();
        let before_replicas: HashSet<String> = metadata
            .full_replicas
            .iter()
            .filter(|(peer, _)| peer == device_id)
            .map(|(_, group)| group.clone())
            .collect();
        let next_replicas: HashSet<String> =
            full_replica_groups.intersection(authorized_groups).cloned().collect();
        let key_changed = match signing_key {
            Some(key) => metadata.signing_keys.insert(device_id.to_string(), key) != Some(key),
            None => metadata.signing_keys.remove(device_id).is_some(),
        };
        metadata.writers.retain(|(peer, _)| peer != device_id);
        metadata
            .writers
            .extend(authorized_groups.iter().cloned().map(|group| (device_id.to_string(), group)));
        metadata.full_replicas.retain(|(peer, _)| peer != device_id);
        metadata
            .full_replicas
            .extend(next_replicas.iter().cloned().map(|group| (device_id.to_string(), group)));
        let changed =
            key_changed || before_writers != *authorized_groups || before_replicas != next_replicas;
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
        self.note_live_netmap_authority();
        // Mirrored whether or not `changed`: the snapshot has to end up
        // agreeing with the state this call leaves behind even when a
        // previous write failed or was never made. (The cache itself
        // decides whether that costs a transaction -- a row already
        // carrying this authorization is not rewritten until its capture
        // time needs refreshing.) A mid-pass identity seed mirrors
        // nothing; see `SnapshotMirror`.
        if mirror == SnapshotMirror::Now {
            self.persist_peer_authorization(device_id);
        }
        changed
    }

    /// Records (or clears) whether `device_id` may write `group_id`, derived
    /// from the netmap's per-group share roles. Returns whether anything
    /// changed; the generation bump happens under the metadata lock.
    pub(super) fn set_peer_group_writer(
        &self,
        device_id: &str,
        group_id: &str,
        is_writer: bool,
    ) -> bool {
        let mut metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let key = (device_id.to_string(), group_id.to_string());
        let changed =
            if is_writer { metadata.writers.insert(key) } else { metadata.writers.remove(&key) };
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
        self.note_live_netmap_authority();
        self.persist_peer_authorization(device_id);
        changed
    }

    /// Current netmap-authorization generation. A version-present confirmation
    /// captures this before its peer round-trip and requires it unchanged after
    /// the reply (see `DaemonState::confirm_version_present_via_peer`).
    pub fn membership_generation(&self) -> u64 {
        self.membership_generation.load(std::sync::atomic::Ordering::Acquire)
    }

    fn bump_membership_generation(&self) {
        self.advance_membership_generation();
        self.peers_changed.send_replace(());
    }

    /// Advances the counter without waking anybody, returning the new
    /// value. For the one caller that has to know the generation BEFORE
    /// its mutation is visible -- it carries that number to disk -- and
    /// must still wake subscribers only once the state they would re-read
    /// is the new one.
    fn advance_membership_generation(&self) -> u64 {
        self.membership_generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1
    }

    /// Every group the netmap authorizes `device_id` for. The other
    /// enumeration direction, for a peer that has just become reachable.
    pub fn authorized_groups_for_peer(&self, device_id: &str) -> Vec<String> {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .writers
            .iter()
            .filter(|(dev, _)| dev == device_id)
            .map(|(_, group)| group.clone())
            .collect()
    }

    /// Every group the netmap records `device_id` as a full replica of.
    pub fn full_replica_groups_for_peer(&self, device_id: &str) -> Vec<String> {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .full_replicas
            .iter()
            .filter(|(dev, _)| dev == device_id)
            .map(|(_, group)| group.clone())
            .collect()
    }

    /// Whether `device_id` is authorized to write `group_id`.
    pub fn peer_is_writer(&self, device_id: &str, group_id: &str) -> bool {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .writers
            .contains(&(device_id.to_string(), group_id.to_string()))
    }

    /// Records (or clears) whether `device_id` syncs `group_id` as a full
    /// replica, derived content-blind from the netmap.
    pub fn set_peer_group_full_replica(
        &self,
        device_id: &str,
        group_id: &str,
        is_full_replica: bool,
    ) {
        let mut metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        let key = (device_id.to_string(), group_id.to_string());
        let changed = if is_full_replica {
            metadata.full_replicas.insert(key)
        } else {
            metadata.full_replicas.remove(&key)
        };
        if changed {
            self.bump_membership_generation();
        }
        drop(metadata);
        self.note_live_netmap_authority();
        self.persist_peer_authorization(device_id);
    }

    /// Whether `device_id` is currently recorded as a full replica of
    /// `group_id` (netmap-derived, content-blind).
    pub fn peer_group_is_full_replica(&self, device_id: &str, group_id: &str) -> bool {
        self.peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .full_replicas
            .contains(&(device_id.to_string(), group_id.to_string()))
    }

    /// Whether any device OTHER than this one is currently recorded
    /// (netmap-derived, content-blind) as an authorized-writer full replica
    /// of `group_id` — the structural fact that makes `AtRisk`
    /// a positively-known conclusion rather than merely
    /// "not yet confirmed": with zero such peers configured, no amount of
    /// waiting for `DurabilityConfirmationJob` will ever produce a
    /// confirmation, so reporting anything but known-insufficient would be
    /// false comfort.
    pub(crate) fn any_other_full_replica_peer_configured(&self, group_id: &str) -> bool {
        let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        metadata.full_replicas.iter().any(|(device_id, gid)| {
            gid == group_id && metadata.writers.contains(&(device_id.clone(), gid.clone()))
        })
    }

    /// Every device id currently netmap-authorized as a WRITER (any
    /// storage mode, not just full-replica) for `group_id` -- the
    /// authoritative "who could theoretically still hold this group's
    /// content" candidate set `known_unobtainable_required_content`
    /// checks membership departure against. Unlike `full_replica_
    /// devices_for_group`, not filtered to full replicas: an OnDemand
    /// device that authored a conflict copy is still its origin, and
    /// still a current member until it genuinely leaves.
    pub(crate) fn current_group_writers(&self, group_id: &str) -> HashSet<String> {
        let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        metadata
            .writers
            .iter()
            .filter(|(_, gid)| gid == group_id)
            .map(|(device_id, _)| device_id.clone())
            .collect()
    }

    /// Every device OTHER than this one currently recorded
    /// (netmap-derived, content-blind) as an authorized-writer full
    /// replica of `group_id` -- the enumerable counterpart to
    /// `any_other_full_replica_peer_configured` above, feeding the
    /// user-facing "Complete copies" per-device list (e.g. "Home NAS --
    /// available/offline"), cross-referenced by the caller against each
    /// device's own current `PeerReachability` to answer "available" vs.
    /// "offline". Order is unspecified (backed by a `HashSet`); callers
    /// needing a stable order should sort.
    pub(crate) fn full_replica_devices_for_group(&self, group_id: &str) -> Vec<String> {
        let metadata = self.peer_netmap_metadata.lock().unwrap_or_else(|p| p.into_inner());
        metadata
            .full_replicas
            .iter()
            .filter(|(_, gid)| gid == group_id)
            .filter(|(device_id, gid)| metadata.writers.contains(&(device_id.clone(), gid.clone())))
            .map(|(device_id, _)| device_id.clone())
            .collect()
    }

    fn group_policies(&self) -> std::sync::MutexGuard<'_, GroupPolicyBook> {
        self.group_policies.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn replace_group_policy_states(&self, states: HashMap<String, GroupPolicyState>) {
        self.group_policies().verified = states;
    }

    pub fn group_policy_state(&self, group_id: &str) -> Option<GroupPolicyState> {
        self.group_policies().verified.get(group_id).cloned()
    }

    /// Applies one verified policy snapshot in a single critical section:
    /// marks every `stale` group stale (refreshing the failure time of one
    /// already marked), clears the stale marker of every `verified` group,
    /// and replaces the whole trusted set with `verified` -- so a group
    /// absent from it is dropped from the trusted set while any stale marker
    /// it already had is left as is. Marking runs before clearing, so a
    /// group in both ends up verified and not stale.
    ///
    /// Returns the groups marked stale, in order. Only the state switch:
    /// `DaemonState::apply_policy_snapshot` is the entry point, and it
    /// revokes each returned group from every live session AFTER this.
    pub(super) fn apply_policy_snapshot(
        &self,
        verified: HashMap<String, GroupPolicyState>,
        stale: Vec<String>,
    ) -> Vec<String> {
        let mut book = self.group_policies();
        let now = now_unix();
        for group_id in &stale {
            book.stale.insert(group_id.clone(), now);
        }
        for group_id in verified.keys() {
            book.stale.remove(group_id);
        }
        #[cfg(test)]
        if let Some(hook) =
            self.policy_snapshot_mid_apply_hook.lock().unwrap_or_else(|p| p.into_inner()).take()
        {
            hook();
        }
        book.verified = verified;
        stale
    }

    #[cfg(test)]
    fn set_policy_snapshot_mid_apply_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.policy_snapshot_mid_apply_hook.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Box::new(hook));
    }

    /// Installs `GroupPolicyState::placeholder_for_tests()` for `group_id`,
    /// without disturbing any other group's entry -- see that constructor's
    /// own doc comment for why a caller outside `change_policy.rs` needs
    /// this rather than building a `GroupPolicyState` literal directly.
    ///
    /// Call after `link_repository().add_link(...)` in a test/benchmark
    /// that constructs a real `DaemonState` (which always starts the
    /// `convergence-engine-scheduler` background task, `maintenance_
    /// coordinator::start`) and injects `FileRecord`s directly rather than
    /// through real signed-delta/native admission. Without a verified
    /// policy entry, `resolve_group_policy` resolves the group to
    /// `Withhold` the moment it is linked (`group_is_introduced` is true).
    /// The thing that actually revokes authorization here is
    /// `NetmapChangeAuthenticator::new` (`change_auth.rs`), whose constructor
    /// eagerly runs `validate_linked_history_best_effort` ->
    /// `restore_group_sessions_if_currently_authorized`. Without
    /// `policy_servable` true on the pass that runs it, it revokes the group
    /// from every peer session -- including ones a raw two-device test
    /// registered by hand -- because `policy_servable` is false regardless of
    /// `peer_is_writer`.
    ///
    /// Retirement used to be a way to reach that constructor: it built a
    /// session per group to run local work through, once, cached, so the
    /// deauthorization it caused was permanent rather than self-healing.
    /// Local work no longer builds anything, so retirement is no longer that
    /// route; a session is still constructed for every real peer, which is
    /// what this helper is for.
    /// Example: a large-file transfer benchmark whose sender-side
    /// CDC chunking runs past the retirement loop's 30s backstop interval
    /// (`RETIREMENT_BACKSTOP_INTERVAL`, `convergence/engine_wrapper.rs`)
    /// would have its destination-side session permanently deauthorized before
    /// `hydration::hydrate()` ever ran, failing every retry with
    /// `HydrationFailed` -- not a hydration bug, but this exact gap.
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_test_group_policy_bootstrap(&self, group_id: &str) {
        self.group_policies()
            .verified
            .insert(group_id.to_string(), GroupPolicyState::placeholder_for_tests());
    }

    /// Installs `policy` as `group_id`'s verified policy, for tests that need
    /// a specific membership (see `GroupPolicyState::with_members_for_tests`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_test_group_policy(&self, group_id: &str, policy: GroupPolicyState) {
        self.group_policies().verified.insert(group_id.to_string(), policy);
    }

    /// Records `group_id`'s policy snapshot as failed at the current time.
    ///
    /// Only the mark: `DaemonState::mark_group_policy_stale` is the entry
    /// point, and it revokes the group from every live session AFTER this.
    pub(super) fn mark_group_policy_stale(&self, group_id: &str) {
        self.group_policies().stale.insert(group_id.to_string(), now_unix());
    }

    /// Clears any stale marker for `group_id` — its policy snapshot verified
    /// again, so admission may resume trusting the verified history.
    pub fn clear_group_policy_stale(&self, group_id: &str) {
        self.group_policies().stale.remove(group_id);
    }

    /// Whether `group_id`'s policy state is currently untrusted (its last
    /// snapshot failed verification and no valid one has replaced it). Both
    /// the daemon's own verification failures and coordinator-flagged
    /// `policyInvalidGroupIds` funnel through `mark_group_policy_stale`, so
    /// this single predicate covers every "do not trust this group" source.
    pub fn is_group_policy_stale(&self, group_id: &str) -> bool {
        self.group_policies().stale.contains_key(group_id)
    }

    /// Whether this device has already been introduced to `group_id` — it is
    /// linked locally (`is_linked`), or the netmap has named some peer as a
    /// writer for it. An introduced group that has no verified policy state
    /// loaded is not a genuinely policy-free group; it is one whose real
    /// policy this process has not resolved yet this run (the startup window
    /// before the netmap orchestrator's first fetch), so its authorization
    /// must fail closed rather than fall back to a placeholder stamp.
    ///
    /// `is_linked` runs only when no netmap writer names the group, and
    /// after the metadata guard has been released.
    fn group_is_introduced(&self, group_id: &str, is_linked: impl FnOnce() -> bool) -> bool {
        if self
            .peer_netmap_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .writers
            .iter()
            .any(|(_, gid)| gid.as_str() == group_id)
        {
            return true;
        }
        is_linked()
    }

    /// The resolution behind `DaemonState::resolve_group_policy` -- see that
    /// method for the full contract. `is_linked` answers whether this device
    /// has a local link row for the group; it is consulted last and only if
    /// needed.
    pub(crate) fn resolve_group_policy(
        &self,
        group_id: &str,
        is_linked: impl FnOnce() -> bool,
    ) -> GroupPolicyResolution {
        {
            // One guard for both, so a concurrent snapshot is seen whole.
            let book = self.group_policies();
            if book.stale.contains_key(group_id) {
                return GroupPolicyResolution::Withhold;
            }
            if let Some(policy) = book.verified.get(group_id) {
                return GroupPolicyResolution::Verified(policy.clone());
            }
        }
        if self.group_is_introduced(group_id, is_linked) {
            GroupPolicyResolution::Withhold
        } else {
            GroupPolicyResolution::Bootstrap
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use super::*;

    const GROUP_A: &str = "group-a";
    const GROUP_B: &str = "group-b";

    fn verified(group_id: &str) -> HashMap<String, GroupPolicyState> {
        HashMap::from([(group_id.to_string(), GroupPolicyState::placeholder_for_tests())])
    }

    /// A reader racing a policy snapshot sees it whole. Every group in both
    /// snapshots is either verified or stale, so `resolve_group_policy`
    /// reaching its "introduced but unresolved" fallback (`is_linked`) means
    /// it observed a group neither trusted nor stale: the window the old
    /// mark / clear / replace sequence left open between clearing a newly
    /// verified group's stale marker and swapping it into the trusted set.
    /// The hook runs a reader at exactly that point and gives it time to
    /// finish; with the snapshot applied under one lock the reader cannot
    /// run until the switch is complete.
    #[test]
    fn a_policy_snapshot_is_observed_whole_by_a_concurrent_reader() {
        let authority = Arc::new(PeerAuthorityState::new());
        assert_eq!(
            authority.apply_policy_snapshot(verified(GROUP_B), vec![GROUP_A.to_string()]),
            vec![GROUP_A.to_string()]
        );
        assert!(authority.is_group_policy_stale(GROUP_A));

        let saw_mixed_state = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = mpsc::channel();
        let (reader_tx, reader_rx) = mpsc::channel();
        {
            let authority = Arc::clone(&authority);
            let saw_mixed_state = Arc::clone(&saw_mixed_state);
            authority.clone().set_policy_snapshot_mid_apply_hook(move || {
                let reader = std::thread::spawn(move || {
                    let resolution = authority.resolve_group_policy(GROUP_A, || {
                        saw_mixed_state.store(true, Ordering::SeqCst);
                        true
                    });
                    let _ = done_tx.send(());
                    resolution
                });
                // Blocked on the lock under the atomic apply; would finish
                // inside the window under the old sequence.
                let _ = done_rx.recv_timeout(Duration::from_millis(250));
                reader_tx.send(reader).unwrap();
            });
        }

        let marked = authority.apply_policy_snapshot(verified(GROUP_A), vec![GROUP_B.to_string()]);
        assert_eq!(marked, vec![GROUP_B.to_string()]);

        let resolution = reader_rx.recv().unwrap().join().unwrap();
        assert!(
            !saw_mixed_state.load(Ordering::SeqCst),
            "a reader observed a group that was neither verified nor stale mid-snapshot"
        );
        assert!(matches!(resolution, GroupPolicyResolution::Verified(_)));
        assert!(!authority.is_group_policy_stale(GROUP_A));
        assert!(authority.group_policy_state(GROUP_A).is_some());
        assert!(authority.is_group_policy_stale(GROUP_B));
        assert!(authority.group_policy_state(GROUP_B).is_none());
    }

    /// A LAN announcement is usable only for a device the netmap both pins
    /// and authorizes: an unknown key, a pinned device with no authorized
    /// group, and a device revoked after it was authorized are all refused.
    #[test]
    fn only_a_pinned_and_authorized_device_is_a_lan_peer() {
        let authority = PeerAuthorityState::new();
        let key = [7u8; 32];
        assert!(!authority.is_authorized_lan_peer(&key), "an unknown key was accepted");

        authority.replace_peer_netmap_metadata(
            "device-b",
            Some(key),
            &HashSet::new(),
            &HashSet::new(),
            SnapshotMirror::Now,
        );
        assert!(
            !authority.is_authorized_lan_peer(&key),
            "a pinned device with no group was accepted"
        );

        let groups = HashSet::from([GROUP_A.to_string()]);
        authority.replace_peer_netmap_metadata(
            "device-b",
            Some(key),
            &groups,
            &HashSet::new(),
            SnapshotMirror::Now,
        );
        assert!(authority.is_authorized_lan_peer(&key));
        assert!(!authority.is_authorized_lan_peer(&[8u8; 32]), "another key rode on device-b");

        authority.replace_peer_netmap_metadata(
            "device-b",
            None,
            &HashSet::new(),
            &HashSet::new(),
            SnapshotMirror::Now,
        );
        assert!(!authority.is_authorized_lan_peer(&key), "a revoked device was still accepted");
    }

    /// The snapshot's exact semantics: failed groups are marked stale
    /// (refreshing an existing mark), verified groups are un-marked, the
    /// trusted set is replaced wholesale, and a group absent from the
    /// snapshot keeps whatever stale marker it had. A group both failed and
    /// verified in one snapshot ends up verified, since marking runs first.
    #[test]
    fn a_policy_snapshot_marks_clears_and_replaces_as_one() {
        let authority = PeerAuthorityState::new();
        authority.apply_policy_snapshot(verified(GROUP_A), vec!["absent".to_string()]);

        let mut both = verified(GROUP_B);
        both.insert("dup".to_string(), GroupPolicyState::placeholder_for_tests());
        let marked =
            authority.apply_policy_snapshot(both, vec![GROUP_A.to_string(), "dup".to_string()]);

        assert_eq!(marked, vec![GROUP_A.to_string(), "dup".to_string()]);
        assert!(authority.is_group_policy_stale(GROUP_A));
        assert!(authority.group_policy_state(GROUP_A).is_none());
        assert!(!authority.is_group_policy_stale(GROUP_B));
        assert!(authority.group_policy_state(GROUP_B).is_some());
        assert!(!authority.is_group_policy_stale("dup"));
        assert!(authority.group_policy_state("dup").is_some());
        assert!(authority.is_group_policy_stale("absent"));
    }
}
