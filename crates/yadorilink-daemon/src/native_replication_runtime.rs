//! Native replication in the live daemon: which peers get a native-replication
//! connection, what each connection may see, and when new local deltas are
//! published and pushed. The protocol logic is in
//! [`crate::native_replication_session`] and the byte-moving in
//! [`crate::native_replication_driver`]; this module binds them to
//! [`DaemonState`] (peer sessions, group authority, keys) and to the
//! endpoint's connections.
//!
//! One connection per peer pair: the device with the smaller endpoint id
//! dials, the other only accepts, so two dials never cross. A connection
//! lives as long as the peer's sync session; it serves the peer's requests
//! and reconciles on attach and on an interval, and new local deltas are
//! pushed the moment they are published.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;
use yadorilink_replica_domain::history_truncation::{HistoryTruncations, RetainedSummary};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::protocol5::RefusalReason;
use yadorilink_sync_substrate::{NativeReplicationConnection, PeerId};

use crate::daemon_state::DaemonState;
use crate::native_replication_driver::{self as driver, GroupRound, ReplicationEnv};

/// How often an attached connection asks its peer for a summary. Live
/// pushes carry the common case; this closes gaps (a peer that was offline
/// when a delta was published, a held delta whose predecessor never came).
/// How long ingest must be silent before a round is started to confirm the replica is in sync.
const INGEST_QUIET: Duration = Duration::from_millis(1500);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(20);

/// The first retry delay after a round that could not make progress (no group is shared yet,
/// or the peer refused or did not answer); each further unproductive round doubles it, up to
/// [`RECONCILE_INTERVAL`]. A missed [`NativeReplicationHub::wake_reconcile`] therefore costs
/// seconds, not the whole interval.
const UNPRODUCTIVE_RETRY_INITIAL: Duration = Duration::from_secs(1);

/// The least time between the starts of two rounds on one connection, however many wake-ups
/// arrive: a burst of changes never turns the loop into a busy one.
const MIN_ROUND_SPACING: Duration = Duration::from_millis(500);

/// A generation counter the reconcile loops wait on. Bumping it makes every waiting loop
/// start its next round now; bumps made while a loop is mid-round or already pending coalesce
/// into one follow-up round, because the loop only compares against the generation it last saw.
pub(crate) struct ReconcileWake(tokio::sync::watch::Sender<u64>);

impl Default for ReconcileWake {
    fn default() -> Self {
        Self(tokio::sync::watch::channel(0).0)
    }
}

pub(crate) struct Live {
    id: u64,
    env: ReplicationEnv,
    connection: NativeReplicationConnection,
    task: tokio::task::JoinHandle<()>,
}

/// The exclusive right to drive one group's rebootstrap machine in this process.
pub(crate) struct MachineClaim {
    hub: Arc<NativeReplicationHub>,
    group: String,
}

impl Drop for MachineClaim {
    fn drop(&mut self) {
        self.hub.machines.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.group);
    }
}

/// The live native replication connections, by peer device.
#[derive(Default)]
pub struct NativeReplicationHub {
    live: Mutex<HashMap<String, Live>>,
    next_id: std::sync::atomic::AtomicU64,
    seals: crate::native_recovery::SealLog,
    /// What each connected peer has said about the history it retains.
    truncations: Mutex<HistoryTruncations>,
    /// The groups whose rebootstrap machine is being driven by this process right now.
    machines: Mutex<std::collections::HashSet<String>>,
    /// Wakes every connection's reconcile loop; see [`Self::wake_reconcile`].
    reconcile_wake: ReconcileWake,
    /// Counts ingest activity; see [`Self::wake_when_ingest_goes_quiet`].
    ingest_seq: std::sync::atomic::AtomicU64,
    /// Counts ingest activity for the contest-fork pass; see [`Self::fork_when_ingest_goes_quiet`].
    fork_seq: std::sync::atomic::AtomicU64,
    /// Test-only: stops the rebootstrap machine at chosen points.
    #[cfg(any(test, feature = "test-support"))]
    rebootstrap_hook: Mutex<Option<crate::native_rebootstrap::Hook>>,
}

impl NativeReplicationHub {
    /// Test-only: a receiver that sees every later [`Self::wake_reconcile`].
    #[cfg(test)]
    pub(crate) fn subscribe_wake_for_test(&self) -> tokio::sync::watch::Receiver<u64> {
        self.reconcile_wake.0.subscribe()
    }

    /// Asks every connection to reconcile now instead of at the end of its current wait: call
    /// it when something changed that can make a round productive (a group linked here, a
    /// peer authorised for or removed from a group, a session's authorised groups replaced).
    /// Cheap and idempotent; rounds stay serial per connection.
    pub fn wake_reconcile(&self) {
        self.reconcile_wake.0.send_modify(|generation| *generation += 1);
    }

    /// When each group was last sealed for a peer, shared by every
    /// connection's recovery port.
    pub(crate) fn seal_log(&self) -> crate::native_recovery::SealLog {
        self.seals.clone()
    }

    /// What `device` has said it no longer holds the history for, per group: the
    /// checkpoint its retained history begins at and that checkpoint's frontier
    /// root. Empty for a peer that has not refused for that reason.
    pub fn history_truncated_by(
        &self,
        device: &str,
    ) -> std::collections::BTreeMap<FolderGroupId, RetainedSummary> {
        self.truncations.lock().unwrap_or_else(|p| p.into_inner()).truncated_by(device)
    }

    /// Claims `group` for one driver of its rebootstrap machine; `None` when another driver
    /// of this process holds it. Released when the claim is dropped.
    pub(crate) fn claim_machine(self: &Arc<Self>, group: &FolderGroupId) -> Option<MachineClaim> {
        let claimed =
            self.machines.lock().unwrap_or_else(|p| p.into_inner()).insert(group.0.clone());
        claimed.then(|| MachineClaim { hub: self.clone(), group: group.0.clone() })
    }

    /// The hook a test installed to stop the rebootstrap machine at chosen points; none in
    /// production.
    pub(crate) fn rebootstrap_hook(&self) -> Option<crate::native_rebootstrap::Hook> {
        #[cfg(any(test, feature = "test-support"))]
        {
            self.rebootstrap_hook.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            None
        }
    }

    /// A replica that just finished taking a peer's history must learn it is in sync NOW, not at the
    /// next 20 s round: the provider namespace is installed by the in-sync round. Called on every
    /// ingest; the wake fires once, `quiet` after the last call (a burst of batches costs one round).
    pub(crate) fn wake_when_ingest_goes_quiet(self: &Arc<Self>, quiet: Duration) {
        use std::sync::atomic::Ordering;
        let seq = self.ingest_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let hub = Arc::downgrade(self);
        runtime.spawn(async move {
            tokio::time::sleep(quiet).await;
            if let Some(hub) = hub.upgrade() {
                if hub.ingest_seq.load(Ordering::SeqCst) == seq {
                    hub.wake_reconcile();
                }
            }
        });
    }

    /// Runs the contest-fork pass once, `quiet` after the last call: a burst of ingested
    /// batches costs one pass.
    pub(crate) fn fork_when_ingest_goes_quiet(
        self: &Arc<Self>,
        quiet: Duration,
        state: Weak<DaemonState>,
    ) {
        use std::sync::atomic::Ordering;
        let seq = self.fork_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let hub = Arc::downgrade(self);
        runtime.spawn(async move {
            tokio::time::sleep(quiet).await;
            let Some(hub) = hub.upgrade() else { return };
            if hub.fork_seq.load(Ordering::SeqCst) != seq {
                return;
            }
            if let Some(state) = state.upgrade() {
                state.fork_contested_heads_everywhere().await;
            }
        });
    }

    /// Test-only: stops every rebootstrap of this device at the points `hook` refuses.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_rebootstrap_hook_for_test(&self, hook: Option<crate::native_rebootstrap::Hook>) {
        *self.rebootstrap_hook.lock().unwrap_or_else(|p| p.into_inner()) = hook;
    }

    /// Remembers that `device` no longer holds the history this replica needs for `group`.
    pub(crate) fn record_truncation(
        &self,
        device: &str,
        group: &FolderGroupId,
        summary: Option<RetainedSummary>,
    ) {
        let mut truncations = self.truncations.lock().unwrap_or_else(|p| p.into_inner());
        match summary {
            Some(summary) => truncations.record(device, group, summary),
            None => truncations.record_uncovered(device, group),
        }
    }

    /// What every connected peer has said about the history it retains.
    pub(crate) fn truncations_snapshot(&self) -> HistoryTruncations {
        self.truncations.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The peers a connection is attached to.
    pub(crate) fn attached_devices(&self) -> Vec<String> {
        let mut devices: Vec<String> =
            self.live.lock().unwrap_or_else(|p| p.into_inner()).keys().cloned().collect();
        devices.sort();
        devices
    }

    /// One awaited incremental sync pass of `group` with every attached peer that shares it:
    /// ask each for what this replica lacks and wait, at most `cap` in all, until nothing more
    /// is being admitted. Returns how far the group's frontier advanced, which is how many
    /// deltas the pass obtained. A peer that fails or refuses contributes nothing: the pass is
    /// best effort and the ordinary reconciliation continues afterwards.
    pub(crate) async fn catch_up_pass(&self, group: &FolderGroupId, cap: Duration) -> u64 {
        let targets: Vec<(ReplicationEnv, NativeReplicationConnection)> = self
            .live
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|live| (live.env.shares_group)(group))
            .map(|live| (live.env.clone(), live.connection.clone()))
            .collect();
        let deadline = tokio::time::Instant::now() + cap;
        let mut obtained = 0u64;
        for (env, connection) in targets {
            let before = frontier_progress(&env, group).await;
            let round = tokio::time::timeout_at(
                deadline,
                driver::reconcile_group(&env, &connection, group),
            )
            .await;
            if !matches!(round, Ok(GroupRound::Requested { .. })) {
                continue;
            }
            // The peer's answer arrives as pushes the serving loop admits; the pass is over
            // for this peer when the frontier has stood still for a quiet period.
            let mut last = before;
            let mut still_since = tokio::time::Instant::now();
            while tokio::time::Instant::now() < deadline {
                tokio::time::sleep(CATCH_UP_POLL).await;
                let now = frontier_progress(&env, group).await;
                if now != last {
                    last = now;
                    still_since = tokio::time::Instant::now();
                } else if still_since.elapsed() >= CATCH_UP_QUIET {
                    break;
                }
            }
            obtained += last.saturating_sub(before);
        }
        obtained
    }

    /// Records what one reconcile round with `device` showed about its history. A
    /// history-truncated refusal is remembered; a round the peer answered without
    /// refusing forgets it; a failed round or any other refusal says nothing.
    pub(crate) fn note_round(&self, device: &str, group: &FolderGroupId, round: &GroupRound) {
        let mut truncations = self.truncations.lock().unwrap_or_else(|p| p.into_inner());
        match round {
            GroupRound::Refused(RefusalReason::HistoryTruncated {
                checkpoint_id,
                frontier_root,
            }) => {
                truncations.record(
                    device,
                    group,
                    RetainedSummary {
                        checkpoint_id: *checkpoint_id,
                        frontier_root: *frontier_root,
                    },
                );
                tracing::warn!(
                    peer = device,
                    group = %group.0,
                    "native replication: the peer no longer holds the history this replica needs"
                );
            }
            GroupRound::InSync | GroupRound::Requested { .. } | GroupRound::Divergent => {
                truncations.clear(device, group);
            }
            GroupRound::Refused(_) | GroupRound::Failed => {}
        }
    }

    /// Serves and reconciles `connection` for `device`, replacing (and
    /// closing) any earlier connection to it.
    pub fn attach(
        self: &Arc<Self>,
        device: String,
        env: ReplicationEnv,
        connection: NativeReplicationConnection,
    ) {
        self.attach_if(device, env, connection, || true);
    }

    /// [`Self::attach`], unless `admit` -- evaluated while the attachment is
    /// being recorded, so no later attach can interleave between the check
    /// and the record -- says the connection is no longer the device's. The
    /// connection is then closed. Returns whether it was attached.
    pub fn attach_if(
        self: &Arc<Self>,
        device: String,
        env: ReplicationEnv,
        connection: NativeReplicationConnection,
        admit: impl FnOnce() -> bool,
    ) -> bool {
        let (serving_env, serving_connection, serving_device) =
            (env.clone(), connection.clone(), device.clone());
        let hub = Arc::downgrade(self);
        let wake = self.reconcile_wake.0.subscribe();
        let marks = {
            let (local, device, groups) =
                (env.local_device_id.clone(), device.clone(), env.groups.clone());
            move || {
                if yadorilink_fs_platform::join_timeline::is_active() {
                    for group in groups() {
                        yadorilink_fs_platform::join_timeline::mark_with_peer(
                            &local,
                            &group.0,
                            yadorilink_fs_platform::join_timeline::Milestone::PeerSessionUsable,
                            &device,
                        );
                    }
                }
            }
        };
        let attached = self.attach_serving(device, env, connection, admit, async move {
            tokio::select! {
                () = driver::serve(serving_env.clone(), serving_connection.clone()) => {}
                () = reconcile_forever(&serving_env, &serving_connection, &serving_device, &hub, wake) => {}
            }
        });
        if attached {
            marks();
        }
        attached
    }

    /// Records `connection` as `device`'s and runs `serving` until it ends,
    /// then drops the record if it is still this one.
    ///
    /// The entry is inserted before the serving task can finish: a connection
    /// that closes right after it was handed over would otherwise run
    /// `detach_if_current` before the insert, and the dead connection would then
    /// sit here as attached forever, so the dialer never redials. Holding the
    /// lock across the spawn means the task's own detach waits until the entry
    /// exists.
    fn attach_serving(
        self: &Arc<Self>,
        device: String,
        env: ReplicationEnv,
        connection: NativeReplicationConnection,
        admit: impl FnOnce() -> bool,
        serving: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> bool {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let hub = Arc::downgrade(self);
        let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
        if !admit() {
            drop(live);
            connection.close(0, b"peer key changed");
            return false;
        }
        let task = {
            let device = device.clone();
            tokio::spawn(async move {
                serving.await;
                if let Some(hub) = hub.upgrade() {
                    hub.detach_if_current(&device, id);
                }
            })
        };
        let replaced = live.insert(device, Live { id, env, connection, task });
        drop(live);
        if let Some(old) = replaced {
            old.task.abort();
            old.connection.close(0, b"replaced");
        }
        true
    }

    fn detach_if_current(&self, device: &str, id: u64) {
        let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
        if live.get(device).is_some_and(|entry| entry.id == id) {
            live.remove(device);
            drop(live);
            self.forget_truncations(device);
        }
    }

    /// Ends the connection to `device`, if any.
    pub fn detach(&self, device: &str) {
        if let Some(old) = self.live.lock().unwrap_or_else(|p| p.into_inner()).remove(device) {
            old.task.abort();
            old.connection.close(0, b"session ended");
        }
        self.forget_truncations(device);
    }

    fn forget_truncations(&self, device: &str) {
        self.truncations.lock().unwrap_or_else(|p| p.into_inner()).forget_peer(device);
    }

    /// Ends every connection.
    pub fn detach_all(&self) {
        let all: Vec<Live> = self
            .live
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .map(|(_, live)| live)
            .collect();
        for old in all {
            old.task.abort();
            old.connection.close(0, b"detached");
        }
        *self.truncations.lock().unwrap_or_else(|p| p.into_inner()) = HistoryTruncations::default();
    }

    /// The authenticated peer of the connection attached for `device`.
    pub(crate) fn attached_peer(&self, device: &str) -> Option<PeerId> {
        self.live.lock().unwrap_or_else(|p| p.into_inner()).get(device).map(|l| l.connection.peer())
    }

    /// Whether a connection to `device` is attached AS `peer`: an attachment
    /// authenticated as another key (one the netmap has since replaced) does
    /// not count, so the keeper dials the current key's connection.
    pub(crate) fn is_attached_as(&self, device: &str, peer: &PeerId) -> bool {
        self.attached_peer(device).as_ref() == Some(peer)
    }

    /// Ends every attachment whose authenticated key is no longer the one
    /// `pinned` names for its device (replaced, or the device unpinned),
    /// whoever attached it and whatever session stands for the device.
    pub(crate) fn detach_unpinned(&self, pinned: &std::collections::HashMap<String, [u8; 32]>) {
        let stale: Vec<Live> = {
            let mut live = self.live.lock().unwrap_or_else(|p| p.into_inner());
            let devices: Vec<String> = live
                .iter()
                .filter(|(device, l)| pinned.get(*device) != Some(l.connection.peer().as_bytes()))
                .map(|(device, _)| device.clone())
                .collect();
            devices.iter().filter_map(|d| live.remove(d)).collect()
        };
        for old in stale {
            old.task.abort();
            old.connection.close(0, b"peer key changed");
        }
    }

    /// Whether a connection to `device` is attached.
    pub fn is_attached(&self, device: &str) -> bool {
        self.live.lock().unwrap_or_else(|p| p.into_inner()).contains_key(device)
    }

    /// Pushes the just-published `hashes` of `group` to every attached peer.
    pub async fn push_published(&self, group: &FolderGroupId, hashes: &[DeltaHash]) {
        let targets: Vec<(ReplicationEnv, NativeReplicationConnection)> = self
            .live
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|live| (live.env.clone(), live.connection.clone()))
            .collect();
        for (env, connection) in targets {
            if (env.shares_group)(group) {
                driver::push_published(&env, &connection, group, hashes).await;
            }
        }
    }
}

/// How often a catch-up pass looks at the group's frontier, and how long it must stand still
/// for the pass to consider a peer's answer delivered.
const CATCH_UP_POLL: Duration = Duration::from_millis(100);
const CATCH_UP_QUIET: Duration = Duration::from_millis(500);

/// The sum of the group's author sequence numbers: it only grows while deltas are admitted.
async fn frontier_progress(env: &ReplicationEnv, group: &FolderGroupId) -> u64 {
    let (db, group) = (env.db.clone(), group.clone());
    tokio::task::spawn_blocking(move || {
        db.read(|conn| {
            yadorilink_sync_sqlite::native_replication::frontier_entries(conn, &group, false)
                .map(|entries| entries.iter().map(|entry| entry.seq.get()).sum::<u64>())
        })
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(0)
}

/// While behind, ask again soon (an answer is capped, and its pushes take a
/// moment to land); once in sync, only on the slow interval.
const CATCH_UP_INTERVAL: Duration = Duration::from_secs(2);

/// What one reconcile round came to, as far as pacing the next one is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoundOutcome {
    /// The peer has more: ask again soon.
    Behind,
    /// Every shared group is in sync: the slow interval is enough.
    Healthy,
    /// Nothing to reconcile yet, or the peer refused or did not answer: retry with backoff.
    Unproductive,
}

fn outcome_of<'a>(rounds: impl IntoIterator<Item = &'a GroupRound>) -> RoundOutcome {
    let (mut any, mut behind, mut unproductive) = (false, false, false);
    for round in rounds {
        any = true;
        match round {
            GroupRound::Requested { .. } => behind = true,
            GroupRound::Refused(_) | GroupRound::Failed => unproductive = true,
            GroupRound::InSync | GroupRound::Divergent => {}
        }
    }
    if behind {
        RoundOutcome::Behind
    } else if !any || unproductive {
        RoundOutcome::Unproductive
    } else {
        RoundOutcome::Healthy
    }
}

/// Runs `round` forever, one at a time: after each, waits for its outcome's delay or for
/// `wake` to change, whichever is first, and never starts two rounds closer than
/// [`MIN_ROUND_SPACING`]. A wake that arrives during a round makes the next one start right
/// after it (one round however many wakes).
async fn run_paced<F, Fut>(mut wake: tokio::sync::watch::Receiver<u64>, mut round: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = RoundOutcome>,
{
    let mut retry = UNPRODUCTIVE_RETRY_INITIAL;
    loop {
        let started = tokio::time::Instant::now();
        let delay = match round().await {
            RoundOutcome::Behind => {
                retry = UNPRODUCTIVE_RETRY_INITIAL;
                CATCH_UP_INTERVAL
            }
            RoundOutcome::Healthy => {
                retry = UNPRODUCTIVE_RETRY_INITIAL;
                RECONCILE_INTERVAL
            }
            RoundOutcome::Unproductive => {
                let delay = retry;
                retry = (retry * 2).min(RECONCILE_INTERVAL);
                delay
            }
        };
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = async {
                if wake.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
        tokio::time::sleep_until(started + MIN_ROUND_SPACING).await;
    }
}

/// A provider root's namespace is installed once this replica is in sync with a peer (the whole
/// native state is here), however it got there; any other round proves nothing about completeness.
/// A failure is retried by the next round.
fn note_provider_install(
    db: &Arc<yadorilink_sqlite_runtime::SyncDatabase>,
    group: &FolderGroupId,
    round: &GroupRound,
) {
    if !matches!(round, GroupRound::InSync) {
        return;
    }
    let repo = yadorilink_sync_sqlite::provider::ProviderRepository::new(db.clone());
    if let Err(error) = repo.mark_installed_when_in_sync(&group.0) {
        tracing::warn!(group = %group.0, %error, "could not record the provider root as installed");
    }
}

async fn reconcile_forever(
    env: &ReplicationEnv,
    connection: &NativeReplicationConnection,
    device: &str,
    hub: &Weak<NativeReplicationHub>,
    wake: tokio::sync::watch::Receiver<u64>,
) {
    run_paced(wake, || async {
        let rounds = driver::reconcile(env, connection).await;
        for (group, round) in &rounds {
            if let Some(hub) = hub.upgrade() {
                hub.note_round(device, group, round);
            }
            note_provider_install(&env.db, group, round);
            match round {
                GroupRound::InSync => {}
                GroupRound::Requested { newer } => {
                    tracing::debug!(peer = device, group = %group.0, newer, "native replication: requested a frontier diff");
                }
                GroupRound::Divergent => {
                    // Not an error by itself: it is also what a replica that is AHEAD of a slow peer
                    // sees (the peer has nothing newer for us and will pull what it lacks). Only a
                    // difference that persists with the peer connected and current points at a
                    // retirement or a fork.
                    tracing::debug!(
                        peer = device,
                        group = %group.0,
                        "native replication: roots differ and the peer has nothing newer for us (we may be ahead of it)"
                    );
                }
                GroupRound::Refused(reason) => {
                    tracing::debug!(peer = device, group = %group.0, ?reason, "native replication: refused");
                }
                GroupRound::Failed => {
                    tracing::debug!(peer = device, group = %group.0, "native replication: round failed");
                }
            }
        }
        outcome_of(rounds.iter().map(|(_, round)| round))
    })
    .await
}

/// What a connection to `device` may see and how its deltas are verified,
/// read from live daemon state on every use so a revocation applies at
/// once.
pub fn env_for_peer(state: &Arc<DaemonState>, device: &str) -> ReplicationEnv {
    let weak: Weak<DaemonState> = Arc::downgrade(state);
    let device = device.to_string();

    let groups = {
        let (weak, device) = (weak.clone(), device.clone());
        move || -> Vec<FolderGroupId> {
            let Some(state) = weak.upgrade() else { return Vec::new() };
            let Some(session) = state.peers.session(&device) else { return Vec::new() };
            let Ok(links) = state.replica_coordinator.link_repository().list_links() else {
                return Vec::new();
            };
            let mut groups: Vec<String> = links
                .into_iter()
                .filter(|link| !link.paused && !link.orphaned)
                .map(|link| link.group_id)
                .filter(|group| session.shares_group(group))
                .collect();
            groups.sort();
            groups.dedup();
            groups.into_iter().map(FolderGroupId).collect()
        }
    };
    let groups = Arc::new(groups);
    let shares_group = {
        let groups = groups.clone();
        move |group: &FolderGroupId| groups().contains(group)
    };
    let key_for = {
        let weak = weak.clone();
        move |author: &yadorilink_replica_domain::author::AuthorId| -> Option<VerifyingKey> {
            let state = weak.upgrade()?;
            let bytes = if author.device.0 == state.device_id {
                state.device_signing_key()?.verifying_key().to_bytes()
            } else {
                state.authority.peer_signing_key(&author.device.0)?
            };
            VerifyingKey::from_bytes(&bytes).ok()
        }
    };
    let authority_key = {
        let weak = weak.clone();
        move |group: &FolderGroupId,
              key_id: &[u8; 32],
              policy_head: &[u8; 32]|
              -> Option<VerifyingKey> {
            weak.upgrade()?
                .authority
                .group_policy_state(&group.0)?
                .resolve_authority_key(key_id, policy_head)
        }
    };
    let policy_point = {
        let weak = weak.clone();
        move |group: &FolderGroupId,
              checkpoint: &yadorilink_replica_domain::authorization_checkpoint::AuthorizationCheckpoint|
              -> bool {
            weak.upgrade()
                .and_then(|state| state.authority.group_policy_state(&group.0))
                .is_some_and(|policy| {
                    policy.writer_at_policy_point(
                        &checkpoint.device_id,
                        &checkpoint.signing_key_fingerprint,
                        checkpoint.policy_seq,
                        &checkpoint.policy_head,
                    )
                })
        }
    };
    let db = state.replica_coordinator.database();
    let activity_state = weak.clone();
    let truncated = {
        let (weak, device) = (weak.clone(), device.clone());
        move |group: &FolderGroupId, summary: Option<RetainedSummary>| {
            if let Some(state) = weak.upgrade() {
                state.native_replication.record_truncation(&device, group, summary);
            }
        }
    };
    ReplicationEnv {
        db,
        counters: state.telemetry.replication_counters(),
        local_device_id: state.device_id.clone(),
        shares_group: Arc::new(shares_group),
        key_for: Arc::new(key_for),
        authority_key: Arc::new(authority_key),
        policy_point: Arc::new(policy_point),
        groups: Arc::new(move || groups()),
        recovery: Arc::new(crate::native_recovery::DaemonRecovery::new(state)),
        recovery_state: Arc::default(),
        truncated: Arc::new(truncated),
        // Peer replication is the daemon's "peer reconciliation activity": it
        // keeps the idle-triggered GC sweep from starting mid-sync.
        activity: Arc::new(move || {
            if let Some(state) = activity_state.upgrade() {
                state.record_activity();
                // Admitted deltas arm projection obligations; without this the engine
                // only notices them on its next poll.
                state.replica_coordinator.notify_materialization_wake();
                state.native_replication.wake_when_ingest_goes_quiet(INGEST_QUIET);
                state
                    .native_replication
                    .fork_when_ingest_goes_quiet(INGEST_QUIET, activity_state.clone());
            }
        }),
    }
}

/// Consumes the endpoint's accepted native replication connections.
pub fn spawn_inbound(
    state: Weak<DaemonState>,
    mut inbound: mpsc::Receiver<NativeReplicationConnection>,
) {
    tokio::spawn(async move {
        while let Some(connection) = inbound.recv().await {
            let Some(state) = state.upgrade() else { return };
            let Some(device) =
                state.authority.device_id_for_signing_key(connection.peer().as_bytes())
            else {
                connection.close(1, b"unknown device");
                continue;
            };
            mark_native_connected(&state, &device);
            let env = env_for_peer(&state, &device);
            state.native_replication.attach(device, env, connection);
        }
    });
}

/// Measurement only: the native replication connection to `device` was
/// dialled or accepted, before it is attached.
fn mark_native_connected(state: &DaemonState, device: &str) {
    if !yadorilink_fs_platform::join_timeline::is_active() {
        return;
    }
    for group in state.authority.authorized_groups_for_peer(device) {
        yadorilink_fs_platform::join_timeline::mark_with_peer(
            &state.device_id,
            &group,
            yadorilink_fs_platform::join_timeline::Milestone::NativeConnected,
            device,
        );
    }
}

/// What one dial attempt came to.
#[derive(Debug, PartialEq, Eq)]
pub enum DialOutcome {
    /// The peer dials this device; nothing to do here.
    NotTheDialer,
    Attached,
    Failed,
}

/// Dials `device` when this device is the one that dials (the smaller
/// endpoint id) and attaches the connection. One attempt; see
/// [`keep_dialed`] for the retrying keeper.
pub async fn dial_if_dialer(
    state: &Arc<DaemonState>,
    endpoint: &crate::peer_connectivity_runtime::IrohEndpoint,
    device: &str,
) -> DialOutcome {
    let Some(key) = state.authority.peer_signing_key(device) else { return DialOutcome::Failed };
    let peer = PeerId::from_bytes(key);
    if endpoint.peer_id() >= peer {
        return DialOutcome::NotTheDialer;
    }
    match endpoint.connect_native_replication(peer).await {
        Ok(connection) => attach_dialed(state, device, connection),
        Err(error) => {
            tracing::debug!(peer = device, %error, "native replication: could not dial the peer");
            DialOutcome::Failed
        }
    }
}

/// Attaches a connection this device dialled to `device`, unless the netmap
/// no longer pins the key it was authenticated as.
///
/// The key a dial was made to is read before the dial and the dial is
/// awaited, so a key replaced in between (the per-peer keeper is replaced,
/// but stopping the old one is asynchronous) must be checked again here:
/// a connection authenticated as the old key is not the device's.
pub(crate) fn attach_dialed(
    state: &Arc<DaemonState>,
    device: &str,
    connection: NativeReplicationConnection,
) -> DialOutcome {
    let still_pinned =
        || state.authority.peer_signing_key(device) == Some(*connection.peer().as_bytes());
    let env = env_for_peer(state, device);
    // Checked where the attachment is recorded, so a replacement keeper's
    // attach cannot slip in between this check and the record.
    if state.native_replication.attach_if(device.to_string(), env, connection.clone(), still_pinned)
    {
        mark_native_connected(state, device);
        DialOutcome::Attached
    } else {
        DialOutcome::Failed
    }
}

/// Keeps a native replication connection to `device` for as long as its
/// sync session is registered: dials with backoff whenever none is attached
/// (a failed dial, or a connection that dropped while the sync carrier
/// stayed up). Ends at once on a device that is not the dialer.
pub async fn keep_dialed(
    state: Weak<DaemonState>,
    stack: Arc<crate::sync_adapter::SyncStack>,
    device: String,
) {
    let mut delay = Duration::from_secs(1);
    loop {
        let Some(state) = state.upgrade() else { return };
        if !state.peers.has_session(&device) {
            return;
        }
        if state.native_replication.is_attached_as(
            &device,
            &PeerId::from_bytes(state.authority.peer_signing_key(&device).unwrap_or_default()),
        ) {
            delay = Duration::from_secs(5);
        } else {
            match dial_if_dialer(&state, stack.endpoint(), &device).await {
                DialOutcome::NotTheDialer => return,
                DialOutcome::Attached => delay = Duration::from_secs(5),
                DialOutcome::Failed => delay = (delay * 2).min(Duration::from_secs(30)),
            }
        }
        drop(state);
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod pacing_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::Instant;

    /// Runs `run_paced` against scripted outcomes (the last repeats) and records when each
    /// round started, relative to the start.
    struct Harness {
        starts: Arc<Mutex<Vec<Duration>>>,
        wake: tokio::sync::watch::Sender<u64>,
        t0: Instant,
        task: tokio::task::JoinHandle<()>,
        /// How long each round itself takes.
        _round_len: Duration,
    }

    fn harness(script: Vec<RoundOutcome>, round_len: Duration) -> Harness {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (wake, rx) = tokio::sync::watch::channel(0u64);
        let t0 = Instant::now();
        let (log, calls) = (starts.clone(), Arc::new(AtomicUsize::new(0)));
        let task = tokio::spawn(run_paced(rx, move || {
            let (log, calls, script) = (log.clone(), calls.clone(), script.clone());
            async move {
                log.lock().unwrap().push(Instant::now() - t0);
                tokio::time::sleep(round_len).await;
                let n = calls.fetch_add(1, Ordering::SeqCst);
                script[n.min(script.len() - 1)]
            }
        }));
        Harness { starts, wake, t0, task, _round_len: round_len }
    }

    impl Harness {
        fn signal(&self) {
            self.wake.send_modify(|generation| *generation += 1);
        }
        fn starts(&self) -> Vec<Duration> {
            self.starts.lock().unwrap().clone()
        }
        async fn until(&self, at: Duration) {
            tokio::time::sleep_until(self.t0 + at).await;
            // Let the loop task run everything due at this instant.
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        }
    }

    const MS: fn(u64) -> Duration = Duration::from_millis;
    const S: fn(u64) -> Duration = Duration::from_secs;

    #[tokio::test(start_paused = true)]
    async fn a_signal_after_an_empty_round_starts_the_next_round_within_a_second() {
        let h = harness(vec![RoundOutcome::Unproductive, RoundOutcome::Healthy], Duration::ZERO);
        h.until(MS(100)).await;
        h.signal();
        h.until(MS(600)).await;
        assert_eq!(h.starts(), vec![S(0), MS(500)], "the signal beats the 1 s retry");
        h.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_signal_wakes_a_healthy_loop_out_of_the_steady_state_wait() {
        let h = harness(vec![RoundOutcome::Healthy], Duration::ZERO);
        h.until(S(3)).await;
        h.signal();
        h.until(S(4)).await;
        assert_eq!(h.starts(), vec![S(0), S(3)]);
        h.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn unproductive_rounds_retry_with_a_doubling_delay_up_to_the_interval() {
        let h = harness(vec![RoundOutcome::Unproductive], Duration::ZERO);
        h.until(S(75)).await;
        let starts = h.starts();
        let gaps: Vec<Duration> = starts.windows(2).map(|w| w[1] - w[0]).collect();
        assert_eq!(gaps, vec![S(1), S(2), S(4), S(8), S(16), S(20), S(20)]);
        h.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_productive_round_resets_the_retry_delay() {
        let h = harness(
            vec![
                RoundOutcome::Unproductive,
                RoundOutcome::Unproductive,
                RoundOutcome::Behind,
                RoundOutcome::Unproductive,
            ],
            Duration::ZERO,
        );
        h.until(S(8)).await;
        let starts = h.starts();
        // 1 s, 2 s, then Behind waits 2 s, then the retry starts over at 1 s.
        assert_eq!(starts[..5], [S(0), S(1), S(3), S(5), S(6)]);
        h.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_healthy_round_waits_the_full_interval_and_does_not_spin() {
        let h = harness(vec![RoundOutcome::Healthy], Duration::ZERO);
        h.until(S(19)).await;
        assert_eq!(h.starts(), vec![S(0)]);
        h.until(S(21)).await;
        assert_eq!(h.starts(), vec![S(0), S(20)]);
        h.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_signals_is_one_round_and_respects_the_minimum_spacing() {
        let h = harness(vec![RoundOutcome::Healthy], Duration::ZERO);
        h.until(MS(10)).await;
        for _ in 0..50 {
            h.signal();
        }
        h.until(MS(499)).await;
        assert_eq!(h.starts(), vec![S(0)], "not before the minimum spacing");
        h.until(S(5)).await;
        assert_eq!(h.starts(), vec![S(0), MS(500)], "one round for the whole burst");
        h.task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_signal_during_a_round_causes_exactly_one_follow_up() {
        let h = harness(vec![RoundOutcome::Healthy], S(2));
        h.until(S(1)).await; // mid-round
        h.signal();
        h.signal();
        h.until(S(3)).await;
        // The round ends at 2 s; the pending signal starts the next at once.
        assert_eq!(h.starts(), vec![S(0), S(2)]);
        h.until(S(15)).await;
        assert_eq!(h.starts(), vec![S(0), S(2)], "the follow-up is not repeated");
        h.task.abort();
    }

    #[test]
    fn outcomes_classify_rounds() {
        let refused = GroupRound::Refused(RefusalReason::Unauthorized);
        assert_eq!(outcome_of([]), RoundOutcome::Unproductive);
        assert_eq!(outcome_of([&GroupRound::InSync]), RoundOutcome::Healthy);
        assert_eq!(outcome_of([&GroupRound::InSync, &refused]), RoundOutcome::Unproductive);
        assert_eq!(outcome_of([&GroupRound::Failed]), RoundOutcome::Unproductive);
        assert_eq!(
            outcome_of([&refused, &GroupRound::Requested { newer: 1 }]),
            RoundOutcome::Behind
        );
    }
}

#[cfg(test)]
mod provider_install_tests {
    use super::*;
    use yadorilink_replica_domain::session_state::ProviderKind;

    /// Only a round that proved the replica in sync installs a joined provider root; every other
    /// outcome leaves it waiting (the namespace verification then still checks the rows).
    #[test]
    fn only_an_in_sync_round_installs_a_provider_root() {
        let coordinator = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
        coordinator.link_repository().add_link("provider://t", "g").unwrap();
        let root = coordinator
            .provider_repository()
            .declare_root("g", ProviderKind::MacFileProvider, "Photos")
            .unwrap();
        let db = coordinator.database().clone();
        db.write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("UPDATE provider_roots SET install_done = 0", [])?;
            Ok(())
        })
        .unwrap();
        let group = FolderGroupId("g".into());
        let installed = || coordinator.provider_repository().install_done_for_tests(&root);

        for round in [
            GroupRound::Requested { newer: 2 },
            GroupRound::Divergent,
            GroupRound::Refused(RefusalReason::Unauthorized),
            GroupRound::Failed,
        ] {
            note_provider_install(&db, &group, &round);
            assert!(!installed(), "{round:?} must not install");
        }
        // Another group's in-sync round says nothing about this one.
        note_provider_install(&db, &FolderGroupId("other".into()), &GroupRound::InSync);
        assert!(!installed());

        note_provider_install(&db, &group, &GroupRound::InSync);
        assert!(installed());
        note_provider_install(&db, &group, &GroupRound::InSync);
        assert!(installed(), "repeating is harmless");
    }
}

#[cfg(test)]
mod ingest_quiet_tests {
    use super::*;

    /// A burst of ingest wakes reconciliation once, after it goes quiet, and not before.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_ingest_wakes_one_round_after_it_goes_quiet() {
        let hub = Arc::new(NativeReplicationHub::default());
        let mut woken = hub.subscribe_wake_for_test();
        let quiet = Duration::from_millis(1500);
        for _ in 0..5 {
            hub.wake_when_ingest_goes_quiet(quiet);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(!woken.has_changed().unwrap(), "woke while ingest was still going on");
        tokio::time::sleep(Duration::from_millis(1600)).await;
        assert!(woken.has_changed().unwrap(), "no round was started after ingest went quiet");
        assert_eq!(*woken.borrow_and_update(), 1, "one wake for the whole burst");
    }
}
