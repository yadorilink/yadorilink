//! What the first live netmap of a run does to the last-known-good
//! authorization the daemon started on.
//!
//! The snapshot on disk is this device's memory of what the coordination
//! plane last told it, kept so a restart taken while that plane is
//! unreachable can go on syncing with peers on the same local network. It is
//! never an authority, and the moment a live netmap arrives it stops being
//! the answer: the netmap replaces it whole, which includes withdrawing
//! every peer the netmap no longer names.
//!
//! That last half is what these tests are about. Applying a netmap is
//! otherwise additive per peer -- a peer it names is admitted, pinned and
//! published -- so the only thing that expresses a removal is the diff
//! against the netmap this device was acting on. Starting that diff from an
//! empty map, as a fresh process once did, meant the first netmap of a run
//! could not remove anybody: a restored peer the plane had already deleted
//! kept its pinned key and its groups until some LATER netmap happened to
//! remove it, which for a deleted device never comes.
//!
//! # Level
//!
//! Daemon lib, over a real on-disk index reopened by a second `DaemonState`
//! -- the same shape as this crate's other restart tests, and the smallest
//! level at which "restart" is a real event. The netmap goes in through
//! `apply_netmap_membership`, the function the WebSocket receive loop calls
//! once a frame has been admitted as an authoritative snapshot; what the
//! loop adds on top of it (parsing, generation admission, the per-peer
//! two-phase pass) has its own tests next door.

#![cfg(test)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{apply_netmap_membership, NetmapDiffState};
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_transport::NetmapSnapshot;

/// The plane snapshot generation the persisted cache is captured at in the
/// tests that care about frame ordering. Any non-zero value works; a
/// round number leaves room on both sides for an older and a newer frame.
const CACHE_SNAPSHOT_GENERATION: u64 = 100;

const REMOVED_PEER: &str = "device-b";
const REMOVED_PEER_KEY: [u8; 32] = [11u8; 32];
const KEPT_PEER: &str = "device-c";
const KEPT_PEER_KEY: [u8; 32] = [12u8; 32];
const GROUP: &str = "group-1";

/// A peer the stale frame still names, but with one of its two groups
/// taken away -- the narrowing a refused frame must still apply.
const NARROWED_PEER: &str = "device-d";
const NARROWED_PEER_KEY: [u8; 32] = [13u8; 32];
const SECOND_GROUP: &str = "group-2";

/// One device's durable state, outliving any single `DaemonState` built
/// over it, exactly as a real device's disk outlives its daemon process.
struct Device {
    database: tempfile::TempDir,
    blocks: tempfile::TempDir,
}

impl Device {
    fn new() -> Self {
        Self { database: tempfile::tempdir().unwrap(), blocks: tempfile::tempdir().unwrap() }
    }

    /// Starts a daemon over this device's disk. Nothing here contacts a
    /// coordination plane, so every instance after the first knows its
    /// peers only from the snapshot on disk.
    fn start(&self) -> Arc<DaemonState> {
        let coordinator =
            Arc::new(ReplicaCoordinator::open(self.database.path().join("sync.sqlite3")).unwrap());
        let blocks = Arc::new(SegmentBlockStore::new(self.blocks.path()).unwrap());
        DaemonState::new("device-a".into(), coordinator, blocks)
    }

    /// The device ids the persisted snapshot currently holds.
    fn persisted_peers(&self) -> Vec<String> {
        let coordinator =
            Arc::new(ReplicaCoordinator::open(self.database.path().join("sync.sqlite3")).unwrap());
        let mut peers: Vec<String> = coordinator
            .offline_peer_authorization_repository()
            .all_peer_authorizations()
            .unwrap()
            .into_iter()
            .map(|peer| peer.device_id)
            .collect();
        peers.sort();
        peers
    }
}

/// One full authoritative netmap frame, at plane snapshot generation
/// `generation`, applied the way the WebSocket receive loop applies one
/// that has already been admitted.
fn apply_frame(
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
    generation: u64,
    snapshot: NetmapSnapshot,
) {
    apply_netmap_membership(state, diff_state, generation, snapshot);
}

fn groups(group: &str) -> HashSet<String> {
    HashSet::from([group.to_string()])
}

/// What a full netmap says about one peer, applied the way the netmap
/// application path applies it.
fn authorize(state: &DaemonState, device_id: &str, key: [u8; 32]) {
    state.replace_peer_netmap_metadata(device_id, Some(key), &groups(GROUP), &HashSet::new());
}

/// The membership half of a full authoritative netmap naming `device_ids`,
/// each sharing `GROUP`.
fn netmap(device_ids: &[&str]) -> NetmapSnapshot {
    device_ids.iter().map(|id| ((*id).to_string(), groups(GROUP))).collect()
}

/// What a full netmap says about one peer that shares more than one group.
fn authorize_for_groups(state: &DaemonState, device_id: &str, key: [u8; 32], shares: &[&str]) {
    let shares: HashSet<String> = shares.iter().map(|group| (*group).to_string()).collect();
    state.replace_peer_netmap_metadata(device_id, Some(key), &shares, &HashSet::new());
}

/// A live `PeerSyncSession` for `device_id` sharing `shares`, registered
/// the way the session keeper registers a dialled one.
///
/// A real session, because the group-edge half of a netmap diff has
/// nowhere else to land: `revoke_group` is the enforcement step -- from
/// that call on, every in-flight and queued request for the group is
/// refused -- and it is a method on the session, not on the authority. A
/// test with no session would be asserting against nothing.
async fn register_session(
    state: &Arc<DaemonState>,
    device_id: &str,
    shares: &[&str],
) -> Arc<yadorilink_peer_session::peer_session::PeerSyncSession> {
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("device-a", device_id).await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    let session = yadorilink_peer_session::peer_session::PeerSyncSession::over_substrate(
        "device-a".to_string(),
        device_id.to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        shares.iter().map(|group| (*group).to_string()).collect(),
        transports,
        super::peer_sync_session_deps(state),
    );
    state.peers.register_session(device_id.to_string(), session.clone(), state.local_convergence());
    session
}

/// A refused first frame withholds what acts on its SILENCE, and nothing
/// else. The group a frame stops listing for a peer it still names is that
/// frame narrowing the peer, and a narrowing is the fail-closed direction:
/// withholding it leaves this device serving a group the netmap in hand
/// says the peer has lost, until some later frame happens to say it again.
///
/// So the same stale frame does both things at once here, which is what
/// makes the split observable: it revokes the group edge it no longer
/// names, and it does not tear down or un-persist the peer it is merely
/// silent about.
#[tokio::test]
async fn a_refused_first_frame_still_revokes_a_group_edge_it_no_longer_names() {
    let device = Device::new();
    {
        let first = device.start();
        first.authority.note_applied_snapshot_generation(CACHE_SNAPSHOT_GENERATION);
        authorize_for_groups(&first, NARROWED_PEER, NARROWED_PEER_KEY, &[GROUP, SECOND_GROUP]);
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
    }

    let restarted = device.start();
    let session = register_session(&restarted, NARROWED_PEER, &[GROUP, SECOND_GROUP]).await;
    assert!(
        session.shares_group(SECOND_GROUP),
        "sanity check: the restored peer's session carries both groups before the frame"
    );

    // Older than the cache it would prune, so it may not act on its
    // silence -- but it names the narrowed peer, and lists only one of
    // that peer's two groups.
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    let stale: NetmapSnapshot = HashMap::from([(NARROWED_PEER.to_string(), groups(GROUP))]);
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION - 1, stale);

    assert!(
        !session.shares_group(SECOND_GROUP),
        "a group the frame stops listing for a peer it DOES name is a narrowing stated by the \
         frame itself, not inferred from its silence, and must be applied however stale the \
         frame is -- otherwise the peer goes on being served a group the netmap says it lost"
    );
    assert!(
        session.shares_group(GROUP),
        "and only that group: the groups the frame still lists are untouched"
    );
    assert!(
        restarted.authority.is_authorized_lan_peer(&NARROWED_PEER_KEY),
        "the narrowed peer itself stays authorized -- the frame named it, and narrowing one of \
         its groups is not withdrawing the peer"
    );
    assert!(
        restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "and the destructive half is still withheld: a peer this stale frame is silent about \
         must not be torn down on the strength of a replay"
    );
    assert_eq!(
        device.persisted_peers(),
        vec![REMOVED_PEER.to_string(), NARROWED_PEER.to_string()],
        "no row is deleted either: both peers' cache rows survive a frame too old to prune"
    );
}

/// A device restored from the offline cache, and then a live netmap that
/// does not name it: it must be gone -- unauthorized, unpinned, its live
/// connectivity ended, and its row deleted -- and it must stay gone across
/// the next restart, because the row is what a restart reads.
///
/// The control in the same run is the peer the netmap DOES name: without it
/// this would pass on a daemon that simply forgot everybody.
///
/// # What the connectivity half does and does not cover
///
/// A real link is recorded for the peer before the netmap arrives, so
/// "its connections are ended" is an observable that can fail: the
/// assertion below is against state the withdrawal has to reach, not
/// against a peer that never had any. What it does NOT cover is a live
/// `PeerSyncSession`, which cannot be constructed here -- one requires
/// real `SessionTransports`, so a daemon-lib fixture with no iroh
/// endpoint has no route to one, and asserting `!has_session` here would
/// be asserting that nothing exists where nothing was ever made. Session
/// teardown on withdrawal is `peer_connectivity_runtime`'s own subject.
#[tokio::test]
async fn the_first_live_netmap_withdraws_a_restored_peer_it_does_not_name() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
    }

    let restarted = device.start();
    assert!(
        restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "sanity check: the restart starts out acting on the last-known-good snapshot"
    );
    assert_eq!(device.persisted_peers(), vec![REMOVED_PEER.to_string(), KEPT_PEER.to_string()]);

    // A real link to the peer about to be withdrawn, so the teardown has
    // something to tear down.
    restarted.peer_connectivity.record_link_up(REMOVED_PEER, None);
    assert!(
        restarted.peer_connectivity.reachability(REMOVED_PEER).is_some(),
        "sanity check: the peer is reachable before the netmap withdraws it"
    );

    // The plane has since removed one of them. This is the first netmap of
    // the run, and it is authoritative: what it does not name is not
    // authorized.
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION, netmap(&[KEPT_PEER]));

    assert!(
        !restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "a peer the first live netmap of the run does not name must not stay authorized on \
         the strength of the disk snapshot: the netmap replaces it"
    );
    assert_eq!(
        restarted.authority.peer_signing_key(REMOVED_PEER),
        None,
        "its pinned key must be withdrawn, so a fresh connection from it is refused rather \
         than merely the current one closed"
    );
    assert!(
        restarted.authority.authorized_groups_for_peer(REMOVED_PEER).is_empty(),
        "it must carry no group authorization either"
    );
    assert!(
        restarted.peer_connectivity.reachability(REMOVED_PEER).is_none(),
        "and the connectivity it still had must be ended, not merely left to notice on its own"
    );
    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "the withdrawal has to reach disk, or the next restart restores the peer the plane \
         removed"
    );

    // Control, and the "stays gone" half: another restart taken offline
    // must not resurrect it.
    let restarted_again = device.start();
    assert!(
        !restarted_again.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "a peer a live netmap withdrew must not come back on a later offline restart"
    );
    assert!(
        restarted_again.authority.is_authorized_lan_peer(&KEPT_PEER_KEY),
        "control: the peer that netmap still named is still authorized after restarting"
    );
}

/// The control at its own level: a restored peer the first netmap DOES name
/// is left exactly as it was -- same key, same groups, same row.
#[tokio::test]
async fn a_restored_peer_the_first_live_netmap_names_is_untouched() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
    }

    let restarted = device.start();
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION, netmap(&[KEPT_PEER]));

    assert!(
        restarted.authority.is_authorized_lan_peer(&KEPT_PEER_KEY),
        "a peer the netmap still names must stay authorized"
    );
    assert_eq!(
        restarted.authority.authorized_groups_for_peer(KEPT_PEER),
        vec![GROUP.to_string()],
        "and keep the groups it was restored with -- the netmap named the same share"
    );
    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "its row must survive the reconciliation that deleted the peers the netmap dropped"
    );
}

/// A row too old for the offline horizon is not restored into memory, so
/// the netmap diff has nothing to tear down for it -- and without the
/// one-shot disk reconciliation the row would sit on disk across every
/// later run. The first live netmap deletes it, because that netmap is this
/// device's opportunity to learn the device is gone.
#[tokio::test]
async fn the_first_live_netmap_deletes_a_row_too_stale_to_have_been_restored() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
    }
    // Older than the horizon: the restart ignores it but leaves it on disk.
    {
        let coordinator = Arc::new(
            ReplicaCoordinator::open(device.database.path().join("sync.sqlite3")).unwrap(),
        );
        let repository = coordinator.offline_peer_authorization_repository();
        let mut peer = repository
            .all_peer_authorizations()
            .unwrap()
            .into_iter()
            .find(|peer| peer.device_id == REMOVED_PEER)
            .expect("the peer was stored");
        peer.captured_at_unix = crate::daemon_state::now_unix()
            - crate::daemon_state::OFFLINE_AUTHORIZATION_HORIZON_SECS
            - 60;
        // The version counters the repository is given back are the ones
        // it already holds: this rewrite backdates a capture time, and
        // must not pretend to be a newer authorization than it is.
        let versions = repository.snapshot_versions().unwrap();
        repository.store_peer_authorization(&peer, versions).unwrap();
    }

    let restarted = device.start();
    assert!(
        !restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "sanity check: an authorization past the horizon is not acted on"
    );

    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION, netmap(&[KEPT_PEER]));

    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "a stale row the netmap does not name must be deleted rather than left for a future \
         restart to find"
    );
}

/// Pruning is the privilege of a full authoritative snapshot, and only of
/// the first one in a run.
///
/// Every netmap frame carries the plane's entire peer list, so the diff
/// above is always against a complete view; a frame that carries something
/// else -- a Track Send rendezvous grant, or a group policy chain extended
/// rather than resent -- never reaches this path at all. This pins the
/// narrower property the one-shot sweep has to have: it runs once, so a
/// later netmap cannot delete a row for a peer that became authorized
/// between two frames and is therefore on disk without ever having been
/// in a frame's peer list.
///
/// The row that must survive is written mid-run, after the first frame's
/// sweep and before a later frame. That is not an artificial shape: the
/// peer rows of a frame are written by the two-phase pass that runs AFTER
/// this membership half, so at the moment any frame's sweep would run,
/// disk is always one step ahead of the peer list that sweep holds. A
/// sweep that ran on every frame would delete exactly that difference.
///
/// The assertion is load-bearing in both directions: the later frame's
/// present set does NOT name the mid-run peer, so a sweep that ran again
/// would delete its row while the daemon still authorizes it in memory --
/// and the daemon would then forget, at its next offline restart, a peer
/// no netmap ever withdrew.
#[tokio::test]
async fn only_the_first_full_snapshot_reconciles_the_persisted_set() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
    }

    let restarted = device.start();
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION, netmap(&[KEPT_PEER]));
    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "sanity check: the first frame's sweep leaves the peer it names alone"
    );

    // Authorized between two frames, so its row is on disk although no
    // frame's peer list has ever carried it.
    authorize(&restarted, REMOVED_PEER, REMOVED_PEER_KEY);
    assert_eq!(
        device.persisted_peers(),
        vec![REMOVED_PEER.to_string(), KEPT_PEER.to_string()],
        "sanity check: the mid-run authorization reached disk"
    );

    // A later frame naming only the peer the first one named. Nothing was
    // withdrawn -- its peer list is unchanged -- so the diff removes
    // nobody, and the sweep must not run a second time and delete the row
    // the frame simply does not know about.
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION + 1, netmap(&[KEPT_PEER]));

    assert!(
        restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "sanity check: the mid-run peer is still authorized in memory, so a row deleted here \
         would be memory and disk disagreeing"
    );
    assert_eq!(
        device.persisted_peers(),
        vec![REMOVED_PEER.to_string(), KEPT_PEER.to_string()],
        "the run's later netmaps express removals through the diff alone; the disk sweep is \
         the first snapshot's business, and re-running it deletes the authorization of a peer \
         the plane never withdrew"
    );
}

/// The membership generation must never go backwards across a restart: a
/// version captured before the restart must not compare equal to one
/// captured after it.
///
/// The peer rows alone cannot carry that. A row is stamped with the
/// generation live when it was WRITTEN, an unchanged row is not rewritten
/// merely to restate a number, and the row carrying the highest generation
/// is exactly the one a withdrawal DELETES -- so taking the maximum over
/// the survivors reads back a generation the previous run had already
/// passed. This is that sequence: two peers authorized, then one removed,
/// then a restart.
#[tokio::test]
async fn the_membership_generation_never_goes_backwards_across_a_restart() {
    let device = Device::new();
    let reached = {
        let first = device.start();
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
        // The withdrawal advances the generation and deletes the row that
        // would otherwise have carried it.
        first.clear_peer_netmap_metadata(REMOVED_PEER);
        let reached = first.authority.membership_generation();
        assert!(reached > 0, "sanity check: the run advanced the generation at all");
        assert_eq!(
            device.persisted_peers(),
            vec![KEPT_PEER.to_string()],
            "sanity check: the withdrawn peer's row is gone, and with it its generation stamp"
        );
        reached
    };

    let restarted = device.start();
    assert!(
        restarted.authority.membership_generation() >= reached,
        "a restart may not hand out a membership generation the previous run had already \
         used: a version-present confirmation compares one captured before a peer round-trip \
         against one captured after it"
    );
}

/// The run's FIRST netmap frame is admitted whatever its generation --
/// nothing this run has seen can rank it -- and it is also the frame with
/// destructive power. An authenticated but replayed frame presented first
/// must therefore not be allowed to prune: what it does not name would be
/// torn down and DELETED from disk, permanently, for peers the plane never
/// withdrew.
///
/// Fail-closed direction intact: the stale frame is still applied, and the
/// peers it names are still authorized from it. Only the destructive half
/// waits.
#[tokio::test]
async fn a_first_frame_older_than_the_persisted_snapshot_deletes_nothing() {
    let device = Device::new();
    {
        let first = device.start();
        first.authority.note_applied_snapshot_generation(CACHE_SNAPSHOT_GENERATION);
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
    }

    let restarted = device.start();
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);

    // Older than the snapshot it would prune: a replay of an answer this
    // device's cache has already moved past.
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION - 1, netmap(&[KEPT_PEER]));

    assert_eq!(
        device.persisted_peers(),
        vec![REMOVED_PEER.to_string(), KEPT_PEER.to_string()],
        "a frame older than the persisted snapshot must delete no row: the deletion is \
         permanent and the frame is not evidence that the plane withdrew anybody"
    );
    assert!(
        restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "and the peer must not be torn down in memory either"
    );

    // The guard is not spent by refusing: the first frame that DOES
    // outrank the snapshot still gets to prune.
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION + 1, netmap(&[KEPT_PEER]));
    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "a frame at least as new as the snapshot prunes, even though a stale one came first"
    );
    assert!(
        !restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "and withdraws the peer in memory with it"
    );
}

/// The control for the test above: a first frame captured at the same
/// plane generation as the persisted snapshot is not stale, and prunes.
/// Without this, the gate could be refusing every first frame and the test
/// above would still pass.
#[tokio::test]
async fn a_first_frame_as_new_as_the_persisted_snapshot_prunes() {
    let device = Device::new();
    {
        let first = device.start();
        first.authority.note_applied_snapshot_generation(CACHE_SNAPSHOT_GENERATION);
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
    }

    let restarted = device.start();
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION, netmap(&[KEPT_PEER]));

    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "a frame as new as the snapshot it prunes is the plane's current answer, not a replay"
    );
    assert!(
        !restarted.authority.is_authorized_lan_peer(&REMOVED_PEER_KEY),
        "and the peer it does not name is withdrawn"
    );
}

/// A frame that is not a netmap snapshot prunes nobody. A Track Send
/// rendezvous grant records a sender for the grant's lifetime and says
/// nothing about who this device's sync peers are, so a restored peer must
/// survive one untouched -- and the grant's sender must not become a sync
/// peer by arriving in it.
#[tokio::test]
async fn a_send_authorization_frame_prunes_nobody() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, KEPT_PEER, KEPT_PEER_KEY);
    }

    let restarted = device.start();
    let _diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);

    super::handle_incoming_send_authorization(
        "grant-1".into(),
        "nonce-1".into(),
        "device-sender".into(),
        [77u8; 32],
        crate::coordination_client::SubstrateReachability::default(),
        crate::daemon_state::now_unix() + 300,
        &restarted,
    );

    assert!(
        restarted.authority.is_authorized_lan_peer(&KEPT_PEER_KEY),
        "a restored peer must survive a frame that is not an authoritative netmap"
    );
    assert_eq!(
        device.persisted_peers(),
        vec![KEPT_PEER.to_string()],
        "and its row must still be on disk"
    );
    assert!(
        !restarted.authority.is_authorized_lan_peer(&[77u8; 32]),
        "the grant's sender is not a sync peer: only a netmap authorizes one"
    );
}

/// What one netmap push costs the disk.
///
/// The snapshot is a mirror, and mirroring must not become the expensive
/// part of applying a netmap: every write is a synchronous SQLite
/// transaction taken on the netmap task while the cache's write-order lock
/// is held. Applying a peer entry touches the authority twice -- an
/// identity seed, then the groups this device's own validation admits --
/// and a plane that re-pushes an unchanged netmap (every reconnect does)
/// used to pay both writes again for every peer, for a row nobody could
/// tell apart from the one already there.
///
/// So: one transaction per peer for what the push actually changed, and
/// nothing at all for a push that restates it. The numbers here are exact
/// rather than an upper bound, because "a bit more than necessary" is how
/// this grew in the first place.
#[tokio::test]
async fn a_netmap_push_costs_one_write_per_peer_and_a_repeat_push_costs_none() {
    const PEERS: usize = 200;

    let device = Device::new();
    let state = device.start();
    let validation_cache = std::sync::Mutex::new(HashMap::new());
    let peers: Vec<(String, [u8; 32])> =
        (0..PEERS).map(|i| (format!("device-{i}"), [(i % 251) as u8; 32])).collect();
    let shares: HashSet<String> = (0..5).map(|group| format!("group-{group}")).collect();

    let push = |state: &Arc<DaemonState>| {
        for (device_id, key) in &peers {
            super::apply_authoritative_peer_metadata(
                state,
                device_id,
                Some(*key),
                &shares,
                &HashSet::new(),
                &validation_cache,
            );
        }
    };

    push(&state);
    let first = state.authority.offline_snapshot_durable_writes();
    assert_eq!(
        first, PEERS,
        "a netmap push must mirror each peer once: the identity seed in the middle of a peer \
         entry is not an authorization anybody restores, and writing it doubled the cost"
    );

    push(&state);
    assert_eq!(
        state.authority.offline_snapshot_durable_writes(),
        first,
        "re-pushing the same netmap must cost nothing: the row on disk already carries this \
         authorization, and its capture time is minutes old, not a day"
    );

    // A real change still reaches disk immediately -- the skip is about
    // restatements, not about batching authorization changes.
    super::apply_authoritative_peer_metadata(
        &state,
        &peers[0].0,
        Some(peers[0].1),
        &HashSet::new(),
        &HashSet::new(),
        &validation_cache,
    );
    assert_eq!(
        state.authority.offline_snapshot_durable_writes(),
        first + 1,
        "a peer whose authorization changed must be written the moment it changes"
    );
}

// ---- custody leases of a requester the plane no longer lists ----

fn lease_request(
    group: &str,
    requester: &str,
) -> yadorilink_sync_sqlite::remote_custody_lease::CustodyLeaseRequest {
    yadorilink_sync_sqlite::remote_custody_lease::CustodyLeaseRequest {
        group_id: group.into(),
        requester_device_id: requester.into(),
        path: "a.bin".into(),
        version_hash: [9; 32],
        blocks: vec!["aa".into()],
        membership_generation: 1,
        attempt_token: [4; 16],
        now_unix: 1,
    }
}

/// Links the groups as this device's eager folders, so it is their full
/// replica and its leases have standing.
fn link_eager(state: &DaemonState, groups: &[&str]) {
    for group in groups {
        state
            .replica_coordinator
            .link_repository()
            .add_link(&format!("/links/{group}"), group)
            .unwrap();
    }
}

fn lease_holders(state: &DaemonState) -> Vec<String> {
    let mut holders: Vec<String> = state
        .replica_coordinator
        .remote_custody_lease_repository()
        .list_active()
        .unwrap()
        .into_iter()
        .map(|lease| format!("{}/{}", lease.group_id, lease.requester_device_id))
        .collect();
    holders.sort();
    holders
}

/// A requester revoked from the group (the plane's next frame no longer lists
/// it) cannot reach this device to release its custody lease, so the frame
/// that drops it drops the lease -- and only that requester's.
#[tokio::test]
async fn a_frame_that_no_longer_lists_a_requester_for_a_group_drops_its_custody_leases() {
    let device = Device::new();
    let state = device.start();
    link_eager(&state, &[GROUP, SECOND_GROUP]);
    let leases = state.replica_coordinator.remote_custody_lease_repository();
    for (group, requester) in
        [(GROUP, REMOVED_PEER), (GROUP, KEPT_PEER), (SECOND_GROUP, REMOVED_PEER)]
    {
        leases.acquire(&lease_request(group, requester)).unwrap();
    }
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&state);

    // REMOVED_PEER is still in the netmap, but no longer shares GROUP.
    let frame: NetmapSnapshot = HashMap::from([
        (REMOVED_PEER.to_string(), groups(SECOND_GROUP)),
        (KEPT_PEER.to_string(), groups(GROUP)),
    ]);
    apply_frame(&state, &diff_state, 1, frame);

    assert_eq!(
        lease_holders(&state),
        vec![format!("{GROUP}/{KEPT_PEER}"), format!("{SECOND_GROUP}/{REMOVED_PEER}")]
    );

    // And a device removed altogether takes the rest of its leases with it.
    apply_frame(&state, &diff_state, 2, netmap(&[KEPT_PEER]));
    assert_eq!(lease_holders(&state), vec![format!("{GROUP}/{KEPT_PEER}")]);
}

/// The run's first frame, older than the authorization cache, may narrow a
/// peer it names but may not act on a peer it is merely silent about: that
/// peer's lease stays until a frame that outranks the cache says it is gone.
#[tokio::test]
async fn a_refused_first_frame_does_not_drop_the_leases_of_a_requester_it_is_silent_about() {
    let device = Device::new();
    {
        let first = device.start();
        first.authority.note_applied_snapshot_generation(CACHE_SNAPSHOT_GENERATION);
        authorize(&first, REMOVED_PEER, REMOVED_PEER_KEY);
    }
    let restarted = device.start();
    link_eager(&restarted, &[GROUP]);
    restarted
        .replica_coordinator
        .remote_custody_lease_repository()
        .acquire(&lease_request(GROUP, REMOVED_PEER))
        .unwrap();
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);

    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION - 1, netmap(&[KEPT_PEER]));
    assert_eq!(lease_holders(&restarted), vec![format!("{GROUP}/{REMOVED_PEER}")]);

    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION + 1, netmap(&[KEPT_PEER]));
    assert!(lease_holders(&restarted).is_empty());
}

/// The same frame that lists the requester without the group (a narrowing,
/// which the session-level revocation does apply from a stale frame) must not
/// delete its lease: the frame may predate the group being added, and a lease
/// deleted on it is not restored by the next frame. A frame that outranks the
/// cache does delete it.
#[tokio::test]
async fn a_refused_first_frame_does_not_drop_the_leases_of_a_requester_it_narrows() {
    let device = Device::new();
    {
        let first = device.start();
        first.authority.note_applied_snapshot_generation(CACHE_SNAPSHOT_GENERATION);
        authorize_for_groups(&first, REMOVED_PEER, REMOVED_PEER_KEY, &[GROUP, SECOND_GROUP]);
    }
    let restarted = device.start();
    link_eager(&restarted, &[GROUP]);
    restarted
        .replica_coordinator
        .remote_custody_lease_repository()
        .acquire(&lease_request(GROUP, REMOVED_PEER))
        .unwrap();
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&restarted);
    let narrowing =
        || -> NetmapSnapshot { HashMap::from([(REMOVED_PEER.to_string(), groups(SECOND_GROUP))]) };

    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION - 1, narrowing());
    assert_eq!(lease_holders(&restarted), vec![format!("{GROUP}/{REMOVED_PEER}")]);

    apply_frame(&restarted, &diff_state, CACHE_SNAPSHOT_GENERATION + 1, narrowing());
    assert!(lease_holders(&restarted).is_empty());
}
