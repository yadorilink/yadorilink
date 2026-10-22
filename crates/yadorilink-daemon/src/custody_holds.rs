//! Requester-side custody holds: the single reconciler that ends the leases
//! this device asked other devices to keep.
//!
//! A `remote_custody_hold` row (see [`yadorilink_sync_sqlite::remote_custody_hold`])
//! means "this peer may hold a lease for me on this exact version". The
//! reconciler walks the rows and, for each one, decides from the row and the
//! current authoritative local state whether this device still depends on it:
//!
//! - `requested`: never. No stamp was issued, so nothing relies on it.
//! - `granted`: only while the path is `Remote` (or `Hydrating`/`Evicting`, in
//!   flight towards or away from it) at exactly the held version.
//!
//! Anything else is released: a `CustodyRelease` to the peer, and the row is
//! deleted only after the peer answered that the lease is gone. A peer that is
//! offline or answers no keeps the row, and the next pass retries. Missing a
//! release site can only over-retain, never lose data.
//!
//! The decision and the release happen under the path's lock, taken with
//! `try_lock` (a busy path is skipped and retried when it settles). The
//! eviction takes the same lock around confirm -> `Evicting` -> `Remote`, so a
//! release can never overtake an eviction that is about to rely on the lease.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::CustodyStamp;
use yadorilink_sync_sqlite::remote_custody_hold::{HoldKey, HoldState, RemoteCustodyHold};
use yadorilink_sync_sqlite::remote_custody_lease::AttemptToken;

use crate::daemon_state::{DaemonState, VERSION_PRESENT_QUERY_OVERALL_TIMEOUT};

/// How long the reconciler waits before it tries again when a pass left work
/// it could not finish (a peer offline, a path busy).
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// How long a request to move custody waits for a path another operation holds.
const REHOME_PATH_LOCK_WAIT: Duration = Duration::from_secs(10);

/// The least time between two reconciler passes: wakes that arrive faster (a
/// burst of materializations) are coalesced into one pass after it.
const MIN_PASS_INTERVAL: Duration = Duration::from_secs(1);

/// How long it waits when every remaining hold is one the device still
/// depends on. A hold turns obsolete when a newer version arrives or the file
/// is deleted, which nothing signals, so this bounds how long such a lease is
/// over-retained.
const RECHECK_INTERVAL: Duration = Duration::from_secs(600);

/// When the reconciler runs again on its own: `None` waits for a wake only.
fn next_pass_after(unfinished: bool, holds_remaining: bool) -> Option<Duration> {
    if unfinished {
        Some(RETRY_INTERVAL)
    } else if holds_remaining {
        Some(RECHECK_INTERVAL)
    } else {
        None
    }
}

impl DaemonState {
    /// Asks the connected, currently-authorized full-replica peers, one after
    /// another, to take durable custody of exactly this version, and returns
    /// the stamp of the first that commits a lease and acknowledges. Peers are
    /// asked sequentially so at most one lease is created per call.
    ///
    /// Each peer's `requested` hold is committed before its acquire is sent, so
    /// a lease the peer commits can never exist without a row here, and it
    /// becomes `granted` before the stamp is returned. A peer that denies or
    /// times out keeps its `requested` row (it may have committed and the
    /// answer been lost); the reconciler releases it. The caller must hold the
    /// path's lock, which is what keeps that reconciler from releasing a lease
    /// the caller is about to rely on.
    ///
    /// Authorization is checked before asking a peer and again after its
    /// reply, and the netmap-authorization generation must be unchanged across
    /// the round-trip, as for
    /// [`Self::confirm_version_present_witness_via_peer`].
    pub async fn acquire_custody_lease_via_peer(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self.acquire_custody_lease_excluding(group_id, path, version_hash, blocks, None).await
    }

    /// [`Self::acquire_custody_lease_via_peer`] never asking `excluded`, the
    /// peer whose lease is being moved away.
    pub(crate) async fn acquire_custody_lease_excluding(
        &self,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
        excluded: Option<&str>,
    ) -> Option<CustodyStamp> {
        let sessions = self.peers.all_sessions();
        let peers = sessions
            .iter()
            .map(|(peer_id, _session)| peer_id.clone())
            .filter(|peer_id| Some(peer_id.as_str()) != excluded)
            .filter(|peer_id| self.peer_may_hold_custody(peer_id, group_id))
            .collect();
        let peers = self.existing_holders_first(group_id, path, &version_hash.0, peers);
        let epoch = self.authority.membership_generation();
        self.acquire_custody_lease_with(
            peers,
            epoch,
            group_id,
            path,
            version_hash,
            |peer_id, token| {
                let session = sessions
                    .iter()
                    .find(|(id, _session)| id == peer_id)
                    .map(|(_id, session)| session.clone());
                async move {
                    match session {
                        Some(session) => {
                            session
                                .request_custody_acquire(
                                    group_id,
                                    path,
                                    version_hash,
                                    blocks,
                                    epoch,
                                    token,
                                )
                                .await
                        }
                        None => false,
                    }
                }
            },
        )
        .await
    }

    /// [`Self::acquire_custody_lease_via_peer`] with the acquire RPC supplied,
    /// so the order of the hold writes around it can be observed.
    pub(crate) async fn acquire_custody_lease_with<F, Fut>(
        &self,
        peers: Vec<String>,
        epoch: u64,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        send_acquire: F,
    ) -> Option<CustodyStamp>
    where
        F: Fn(&str, AttemptToken) -> Fut,
        Fut: Future<Output = bool>,
    {
        let holds = self.replica_coordinator.remote_custody_hold_repository();
        tokio::time::timeout(VERSION_PRESENT_QUERY_OVERALL_TIMEOUT, async {
            let deadline = tokio::time::Instant::now() + VERSION_PRESENT_QUERY_OVERALL_TIMEOUT;
            let count = peers.len();
            for (index, peer_id) in peers.into_iter().enumerate() {
                let hold = HoldKey {
                    group_id: group_id.to_string(),
                    path: path.to_string(),
                    version_hash: version_hash.0,
                    peer_id: peer_id.clone(),
                };
                // A new attempt gets a new token; a hold that already exists keeps
                // the token of its first attempt, which is the one a release names.
                let token = match holds.record_requested(&hold, epoch, rand::random()) {
                    Ok(token) => token,
                    Err(error) => {
                        tracing::warn!(%error, "could not record a custody hold; not asking for custody");
                        return None;
                    }
                };
                // A candidate that times out may still have committed; its
                // `requested` row is what lets the reconciler release that.
                // Each candidate gets an equal share of what remains, so a
                // silent one cannot use up the time the later ones need, and
                // the last gets all that is left.
                let budget = deadline.saturating_duration_since(tokio::time::Instant::now())
                    / (count - index) as u32;
                let granted =
                    tokio::time::timeout(budget, send_acquire(&peer_id, token)).await.unwrap_or(false);
                if granted
                    && self.authority.membership_generation() == epoch
                    && self.peer_may_hold_custody(&peer_id, group_id)
                {
                    if let Err(error) = holds.mark_granted(&hold) {
                        tracing::warn!(%error, "could not record a granted custody hold");
                        return None;
                    }
                    return Some(CustodyStamp::new(peer_id, epoch));
                }
            }
            None
        })
        .await
        .unwrap_or(None)
    }

    /// One reconciler pass over every hold. Returns whether some hold could
    /// not be settled (peer unreachable, path busy, an error) and a later pass
    /// should retry.
    pub async fn release_obsolete_custody_holds(&self) -> bool {
        self.reconcile_custody_holds(|hold: RemoteCustodyHold| async move {
            self.release_custody_lease_via_peer(
                &hold.key.peer_id,
                &hold.key.group_id,
                &hold.key.path,
                VersionHash(hold.key.version_hash),
                hold.attempt_token,
            )
            .await
        })
        .await
    }

    /// Wakes the reconciler task: a path this device evicted or hydrated has
    /// settled, so its holds may be obsolete. The wake is remembered if the
    /// task is busy.
    pub fn nudge_custody_hold_reconciler(&self) {
        self.custody_hold_wake.notify_one();
    }

    /// [`Self::release_obsolete_custody_holds`] with the release RPC supplied,
    /// so the decision logic can be driven without a peer.
    pub(crate) async fn reconcile_custody_holds<F, Fut>(&self, release: F) -> bool
    where
        F: Fn(RemoteCustodyHold) -> Fut + Sync,
        Fut: Future<Output = bool> + Send,
    {
        let holds = match self.replica_coordinator.remote_custody_hold_repository().list() {
            Ok(holds) => holds,
            Err(error) => {
                tracing::warn!(%error, "could not list custody holds");
                return true;
            }
        };
        let mut unfinished = false;
        for hold in holds {
            unfinished |= !self.reconcile_one_custody_hold(&hold.key, &release).await;
        }
        unfinished
    }

    /// Settles one hold under its path lock. `false` when it could not be
    /// settled and should be retried.
    async fn reconcile_one_custody_hold<F, Fut>(&self, key: &HoldKey, release: &F) -> bool
    where
        F: Fn(RemoteCustodyHold) -> Fut + Sync,
        Fut: Future<Output = bool> + Send,
    {
        let holds = self.replica_coordinator.remote_custody_hold_repository();
        let path_lock = self.replica_coordinator.path_lock(&key.group_id, &key.path);
        let Ok(_path_guard) = path_lock.try_lock() else {
            return false;
        };
        // Read again under the lock: an eviction that held it may have
        // granted, or an earlier pass deleted, the row listed above.
        let current = match holds.get(key) {
            Ok(Some(current)) => current,
            Ok(None) => return true,
            Err(error) => {
                tracing::warn!(%error, "could not read a custody hold");
                return false;
            }
        };
        if current.state == HoldState::Granted
            && !matches!(self.custody_hold_dependency(key).await, HoldDependency::NotNeeded)
        {
            return true;
        }
        let released =
            tokio::time::timeout(VERSION_PRESENT_QUERY_OVERALL_TIMEOUT, release(current))
                .await
                .unwrap_or(false);
        if !released {
            return false;
        }
        match holds.delete(key) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "could not delete a released custody hold");
                false
            }
        }
    }

    /// Whether this device still depends on the lease: the path is a
    /// placeholder (or moving to or from one) at exactly the held version.
    /// Any read error counts as needed, so an unreadable state never releases.
    async fn custody_hold_dependency(&self, key: &HoldKey) -> HoldDependency {
        let snapshot = match self
            .replica_coordinator
            .as_ref()
            .eviction_revalidation_snapshot(&key.group_id, &key.path)
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(%error, "could not read a path to judge its custody hold");
                return HoldDependency::Unknown;
            }
        };
        let held = snapshot.current_version.filter(|current| {
            !current.deleted && current.to_file_version().version_hash.0 == key.version_hash
        });
        let in_flight = matches!(
            snapshot.materialization_state,
            Some(
                MaterializationState::Remote
                    | MaterializationState::Hydrating
                    | MaterializationState::Evicting
            )
        );
        match held {
            Some(current) if in_flight => {
                let blocks = current.to_file_version().blocks;
                // A provider item is always `Remote` (the OS owns the local copy), so its row
                // says nothing about the lease. The device depends on the lease exactly when
                // some block of the held version is not readable and hash-valid in its own block
                // store (index presence is not enough: releasing the lease gives up the remote
                // copy). The caller holds the item's path lock across this check and the release.
                if self.is_provider_group(&key.group_id)
                    && self.blocks_verified_locally(blocks.clone()).await
                {
                    return HoldDependency::NotNeeded;
                }
                HoldDependency::Needed { blocks }
            }
            _ => HoldDependency::NotNeeded,
        }
    }

    fn is_provider_group(&self, group_id: &str) -> bool {
        // A read error answers false, which leaves the row-state answer (needed) in force.
        matches!(
            self.replica_coordinator.provider_repository().declaration_for_group(group_id),
            Ok(yadorilink_sync_sqlite::provider::ProviderDeclaration::Provider(_))
        )
    }

    /// Answers a full replica that is about to stop being one and asks this
    /// device to take its custody of `version_hash` elsewhere: takes custody
    /// at another full replica when the path still depends on it, then
    /// releases `from_peer`'s lease and forgets the hold. `true` once that
    /// lease is released. `false` when it could not be moved (no other full
    /// replica answered, the path is busy, `from_peer` did not answer the
    /// release) or when this device has no matching hold: a lease nothing here
    /// accounts for is left for its holder to refuse on, never dropped on this
    /// device's word.
    pub(crate) async fn rehome_custody_hold(
        &self,
        from_peer: &str,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        attempt_token: AttemptToken,
    ) -> bool {
        self.rehome_custody_hold_with(
            from_peer,
            group_id,
            path,
            version_hash,
            attempt_token,
            |blocks| async move {
                self.acquire_custody_lease_excluding(
                    group_id,
                    path,
                    version_hash,
                    &blocks,
                    Some(from_peer),
                )
                .await
                .is_some()
            },
            || async move {
                tokio::time::timeout(
                    VERSION_PRESENT_QUERY_OVERALL_TIMEOUT,
                    self.release_custody_lease_via_peer(
                        from_peer,
                        group_id,
                        path,
                        version_hash,
                        attempt_token,
                    ),
                )
                .await
                .unwrap_or(false)
            },
        )
        .await
    }

    /// [`Self::rehome_custody_hold`] with the two peer round trips supplied:
    /// `acquire_elsewhere` takes custody of the version's blocks at a full
    /// replica other than `from_peer`, `release_at_peer` ends `from_peer`'s
    /// lease.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn rehome_custody_hold_with<A, AF, R, RF>(
        &self,
        from_peer: &str,
        group_id: &str,
        path: &str,
        version_hash: VersionHash,
        attempt_token: AttemptToken,
        acquire_elsewhere: A,
        release_at_peer: R,
    ) -> bool
    where
        A: FnOnce(Vec<VersionBlock>) -> AF,
        AF: Future<Output = bool>,
        R: FnOnce() -> RF,
        RF: Future<Output = bool>,
    {
        let key = HoldKey {
            group_id: group_id.to_string(),
            path: path.to_string(),
            version_hash: version_hash.0,
            peer_id: from_peer.to_string(),
        };
        let holds = self.replica_coordinator.remote_custody_hold_repository();
        let path_lock = self.replica_coordinator.path_lock(group_id, path);
        let Ok(_path_guard) = tokio::time::timeout(REHOME_PATH_LOCK_WAIT, path_lock.lock()).await
        else {
            return false;
        };
        let hold = match holds.get(&key) {
            Ok(Some(hold)) if hold.attempt_token == attempt_token => hold,
            Ok(_) => return false,
            Err(error) => {
                tracing::warn!(%error, "could not read a custody hold to move it");
                return false;
            }
        };
        if hold.state == HoldState::Granted {
            match self.custody_hold_dependency(&key).await {
                HoldDependency::Unknown => return false,
                HoldDependency::Needed { blocks } => {
                    if !acquire_elsewhere(blocks).await {
                        return false;
                    }
                }
                HoldDependency::NotNeeded => {}
            }
        }
        release_at_peer().await && holds.delete(&key).is_ok()
    }
}

impl DaemonState {
    /// `peers` with those already holding a granted hold for exactly this
    /// version first, otherwise in the given order. Asking such a peer again is
    /// idempotent when its lease is live (it answers with the same lease) and
    /// refused when it is not, so a retried move reuses the replacement its
    /// earlier attempt took, instead of adding another lease, without trusting
    /// a local row to say the lease still exists.
    fn existing_holders_first(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &[u8; 32],
        mut peers: Vec<String>,
    ) -> Vec<String> {
        let granted = self
            .replica_coordinator
            .remote_custody_hold_repository()
            .granted_peers(group_id, path, version_hash)
            .unwrap_or_default();
        // Stable: false (holders) sorts before true.
        peers.sort_by_key(|peer| !granted.contains(peer));
        peers
    }
}

/// What the local state says about a granted hold.
enum HoldDependency {
    /// A placeholder at the held version: the lease backs it. Carries the
    /// version's blocks, which a new acquire must name.
    Needed { blocks: Vec<VersionBlock> },
    /// Nothing depends on the lease any more.
    NotNeeded,
    /// The state could not be read; treated as needed.
    Unknown,
}

impl yadorilink_peer_session::peer_session::CustodyRehomeResponder for DaemonState {
    fn rehome<'a>(
        &'a self,
        from_peer: &'a str,
        group_id: &'a str,
        file_path: &'a str,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(self.rehome_custody_hold(
            from_peer,
            group_id,
            file_path,
            version_hash,
            attempt_token,
        ))
    }
}

/// Runs the reconciler for the life of the daemon: a pass now (startup, after
/// the stale `Evicting` rows were reset), and again when a peer registers, when
/// nudged, and periodically while a pass left something unfinished. Holds only
/// a weak reference, so it never keeps the daemon alive.
pub fn spawn_custody_hold_reconciler(state: &Arc<DaemonState>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(state);
    let wake = state.custody_hold_wake.clone();
    let mut registrations = state.peers.subscribe_to_registrations();
    tokio::spawn(async move {
        loop {
            let Some(state) = weak.upgrade() else {
                return;
            };
            let unfinished = state.release_obsolete_custody_holds().await;
            let holds_remaining = state
                .replica_coordinator
                .remote_custody_hold_repository()
                .list()
                .map_or(true, |holds| !holds.is_empty());
            drop(state);
            tokio::time::sleep(MIN_PASS_INTERVAL).await;
            let retry = async {
                match next_pass_after(unfinished, holds_remaining) {
                    Some(wait) => tokio::time::sleep(wait).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                () = wake.notified() => {}
                changed = registrations.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                () = retry => {}
            }
        }
    })
}

#[cfg(test)]
mod tests;
