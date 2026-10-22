//! What this device may still do with its peers after a restart taken while
//! the coordination plane is unreachable.
//!
//! Two devices on the same local network are not broken merely because the
//! plane, the relays or the internet are. The authorization that let them
//! sync was verified against the plane while it WAS reachable, and the
//! contract asserted here is that the last such verified authorization
//! remains usable while offline -- a last-known-good authorization snapshot,
//! never an authority of its own:
//!
//! - it never outranks a live netmap: the first netmap after a restart
//!   replaces it wholesale;
//! - it only ever carries peers the plane once authorized, so no peer is
//!   newly authorized while offline;
//! - the signing key it carries is the one that must answer; a different key
//!   announcing the same device is refused;
//! - what a live netmap withdraws is withdrawn from it too, so a revoke is
//!   not undone by restarting.
//!
//! Detecting a revocation that happened at the plane WHILE this device was
//! offline is explicitly not in scope, and nothing here claims it.
//!
//! # Level
//!
//! Daemon lib, over a real on-disk index reopened by a second `DaemonState`
//! -- the same shape as the other restart tests in this crate, and the
//! smallest level at which "restart" is a real event rather than a simulated
//! one. The assertions are on [`PeerAuthorityState::is_authorized_lan_peer`]
//! and its neighbours because that predicate IS what the daemon installs as
//! the local-network lookup policy (`PeerConnectivityRuntime::bind_endpoint`
//! passes it to `with_lan_peers`). That an mDNS answer reaches iroh only
//! through that policy -- refused endpoint, no address, no dial -- is the
//! subject of `yadorilink-sync-substrate`'s own LAN lookup tests, which
//! already dial an authorized peer over a scripted LAN with no directory at
//! all; repeating that here would test iroh, not this device's memory of who
//! its peers are.

#![cfg(test)]

use std::collections::HashSet;
use std::sync::Arc;

use super::{AuthorizationProvenance, DaemonState};
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const PEER: &str = "device-b";
const PEER_KEY: [u8; 32] = [11u8; 32];
/// A second authorized peer, used as the control in the refusal tests: it
/// must survive the same restart the refused peer does not, so a test cannot
/// pass merely because a restarted device authorizes nobody at all.
const OTHER_PEER: &str = "device-c";
const OTHER_PEER_KEY: [u8; 32] = [12u8; 32];
const GROUP: &str = "group-1";

/// One device's durable state: the index database and the block store, both
/// outliving any single `DaemonState` built over them, exactly as a real
/// device's disk outlives its daemon process.
struct Device {
    database: tempfile::TempDir,
    blocks: tempfile::TempDir,
}

impl Device {
    fn new() -> Self {
        Self { database: tempfile::tempdir().unwrap(), blocks: tempfile::tempdir().unwrap() }
    }

    /// Starts a daemon over this device's disk. Nothing here contacts a
    /// coordination plane, so every instance after the first is a restart
    /// taken while the plane is unreachable: whatever it knows about its
    /// peers, it knows from disk.
    fn start(&self) -> Arc<DaemonState> {
        let coordinator =
            Arc::new(ReplicaCoordinator::open(self.database.path().join("sync.sqlite3")).unwrap());
        let blocks = Arc::new(SegmentBlockStore::new(self.blocks.path()).unwrap());
        DaemonState::new("device-a".into(), coordinator, blocks)
    }

    /// Moves one peer's stored capture time `age_secs` into the past,
    /// which is how a test reaches an authorization old enough for the
    /// offline horizon to judge without waiting a week for one.
    fn backdate_peer(&self, device_id: &str, age_secs: i64) {
        let coordinator =
            Arc::new(ReplicaCoordinator::open(self.database.path().join("sync.sqlite3")).unwrap());
        let repository = coordinator.offline_peer_authorization_repository();
        let mut peer = repository
            .all_peer_authorizations()
            .unwrap()
            .into_iter()
            .find(|peer| peer.device_id == device_id)
            .expect("the peer was stored");
        peer.captured_at_unix = crate::daemon_state::now_unix() - age_secs;
        // The version counters the repository is given back are the ones
        // it already holds: this rewrite backdates a capture time, and
        // must not pretend to be a newer authorization than it is.
        let versions = repository.snapshot_versions().unwrap();
        repository.store_peer_authorization(&peer, versions).unwrap();
    }
}

fn groups(group: &str) -> HashSet<String> {
    HashSet::from([group.to_string()])
}

/// Applies what a full netmap says about one peer, the way the netmap
/// application path does.
fn authorize(state: &DaemonState, device_id: &str, key: [u8; 32]) {
    state.replace_peer_netmap_metadata(device_id, Some(key), &groups(GROUP), &HashSet::new());
}

/// A. The requirement: a netmap was fetched once, the daemon stopped, the
/// plane is now unreachable, and the same already-authorized peer is still
/// one this device will accept a local-network address for and dial.
#[tokio::test]
async fn an_authorized_peer_is_still_reachable_on_the_lan_after_an_offline_restart() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, PEER, PEER_KEY);
        assert!(
            first.authority.is_authorized_lan_peer(&PEER_KEY),
            "sanity check: a peer the netmap authorized is a LAN peer while the daemon runs"
        );
    }

    let restarted = device.start();

    assert!(
        restarted.authority.is_authorized_lan_peer(&PEER_KEY),
        "a peer authorized by the last netmap this device verified must still be one it \
         will accept a local-network address for after restarting with no plane to ask"
    );
    assert_eq!(
        restarted.authority.device_id_for_signing_key(&PEER_KEY).as_deref(),
        Some(PEER),
        "the announcement's key must still resolve back to the device it belongs to"
    );
    assert_eq!(
        restarted.authority.authorized_groups_for_peer(PEER),
        vec![GROUP.to_string()],
        "the groups the peer was authorized for must survive too, or the rediscovered \
         connection has nothing to sync"
    );
}

/// B. Offline operation continues an authorization; it never starts one. A
/// device that was never in a netmap this device verified is refused however
/// loudly it announces itself on the local network.
#[tokio::test]
async fn a_peer_never_authorized_is_refused_after_an_offline_restart() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, PEER, PEER_KEY);
    }

    let restarted = device.start();

    // The control: the refusal below must be a decision, not the side effect
    // of a restarted device knowing nobody.
    assert!(
        restarted.authority.is_authorized_lan_peer(&PEER_KEY),
        "control: the peer the last verified netmap authorized must survive the restart"
    );
    let stranger = [99u8; 32];
    assert!(
        !restarted.authority.is_authorized_lan_peer(&stranger),
        "a device absent from the last verified authorization must not become a LAN peer \
         by announcing itself"
    );
    assert!(
        restarted.authority.device_id_for_signing_key(&stranger).is_none(),
        "an unknown key must not resolve to any device"
    );
}

/// C. The persisted authorization names one signing key per device, and that
/// key is the one that must answer. Another key announcing the same device is
/// a different endpoint, and is refused -- fail closed.
#[tokio::test]
async fn a_persisted_peer_announcing_another_signing_key_is_refused() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, PEER, PEER_KEY);
    }

    let restarted = device.start();

    assert!(
        restarted.authority.is_authorized_lan_peer(&PEER_KEY),
        "control: the key the last verified netmap pinned must survive the restart"
    );
    let impostor = [13u8; 32];
    assert!(
        !restarted.authority.is_authorized_lan_peer(&impostor),
        "a key other than the pinned one must not inherit the device's authorization"
    );
    assert!(
        restarted.authority.device_id_for_signing_key(&impostor).is_none(),
        "a mismatched key must resolve to no device at all"
    );
}

/// D. A revoke a live netmap delivered is withdrawn from the offline
/// authorization as well, so restarting does not resurrect it. (This is not a
/// claim about a revocation that happens at the plane while this device is
/// offline -- that is outside the contract.)
#[tokio::test]
async fn a_revoked_peer_stays_revoked_across_an_offline_restart() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, PEER, PEER_KEY);
        authorize(&first, OTHER_PEER, OTHER_PEER_KEY);
        // What a netmap that no longer lists the device does, via
        // `peer_orchestrator::teardown_peer`.
        first.clear_peer_netmap_metadata(PEER);
        assert!(
            !first.authority.is_authorized_lan_peer(&PEER_KEY),
            "sanity check: the revoke takes effect immediately in the running daemon"
        );
    }

    let restarted = device.start();

    assert!(
        restarted.authority.is_authorized_lan_peer(&OTHER_PEER_KEY),
        "control: the peer that was NOT revoked must survive the restart"
    );
    assert!(
        !restarted.authority.is_authorized_lan_peer(&PEER_KEY),
        "a peer a live netmap revoked must not be authorized again by a later restart"
    );
    assert!(
        restarted.authority.device_id_for_signing_key(&PEER_KEY).is_none(),
        "a revoked device's key must not resolve after the restart either"
    );
    assert!(
        restarted.authority.authorized_groups_for_peer(PEER).is_empty(),
        "a revoked device must carry no group authorization after the restart"
    );
}

/// Signing out, or ceasing to be a registered device, leaves no
/// authorization to continue: the snapshot is deleted rather than left on
/// disk for a later restart to act on. (`app::run` calls this on the
/// startup path that finds no credential or no registered device, which is
/// also how a `yadorilink logout` run in another process reaches it.)
#[tokio::test]
async fn signing_out_deletes_the_offline_authorization() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, PEER, PEER_KEY);
        first.forget_offline_peer_authorization();
        assert!(
            !first.authority.is_authorized_lan_peer(&PEER_KEY),
            "sanity check: the running daemon stops authorizing the peer immediately"
        );
    }

    let restarted = device.start();

    assert!(
        !restarted.authority.is_authorized_lan_peer(&PEER_KEY),
        "a peer authorized before this device signed out must not be authorized again by a \
         later restart"
    );
    assert!(
        restarted.authority.device_id_for_signing_key(&PEER_KEY).is_none(),
        "nothing of the signed-out device's peers may survive on disk"
    );
}

/// The restored snapshot is never mistaken for the plane's current answer:
/// a restarted daemon says plainly that it is operating on last-known-good
/// authorization, and the first live netmap it applies takes that back.
#[tokio::test]
async fn a_restarted_daemon_says_it_is_running_on_last_known_good_authorization() {
    let device = Device::new();
    {
        let first = device.start();
        assert_eq!(
            first.authority.authorization_provenance(),
            AuthorizationProvenance::Unestablished,
            "a device that has never seen a netmap holds no authorization at all"
        );
        authorize(&first, PEER, PEER_KEY);
        assert_eq!(
            first.authority.authorization_provenance(),
            AuthorizationProvenance::LiveNetmap,
            "applying a netmap entry is the live authority, not a cache read"
        );
    }

    let restarted = device.start();

    let provenance = restarted.authority.authorization_provenance();
    assert!(
        provenance.is_offline_last_known_good(),
        "a restart with no plane to ask is operating on last-known-good authorization, and must \
         say so rather than look like a device with a current netmap; got {provenance:?}"
    );

    // A live netmap replaces the snapshot as the authoritative answer the
    // moment one arrives.
    authorize(&restarted, OTHER_PEER, OTHER_PEER_KEY);
    assert_eq!(
        restarted.authority.authorization_provenance(),
        AuthorizationProvenance::LiveNetmap,
        "the first netmap of the run supersedes the restored snapshot"
    );
}

/// Deleting the snapshot is a change to who this device's peers are, so the
/// subscribers that act on that -- the connectivity side, which installs the
/// local-network lookup policy and holds the live sessions -- are woken by
/// it like any other. Without the wake a session opened before the deletion
/// would keep running against an authorization that no longer exists.
#[tokio::test]
async fn deleting_the_offline_authorization_wakes_the_peer_change_subscribers() {
    let device = Device::new();
    let state = device.start();
    authorize(&state, PEER, PEER_KEY);

    let changes = state.authority.subscribe_to_peer_changes();
    // A fresh receiver has already seen the current state, so anything it
    // reports from here is this deletion.
    assert!(!changes.has_changed().unwrap(), "sanity check: nothing pending before the deletion");

    state.forget_offline_peer_authorization();

    assert!(
        changes.has_changed().unwrap(),
        "withdrawing every peer must wake the subscribers that hold sessions to them"
    );
}

/// The snapshot is acted on while it is recent, and judged rather than
/// merely dated: an authorization this device has had no chance to
/// re-verify for longer than the offline horizon is one it stops acting on
/// and waits for a live netmap to restate.
#[tokio::test]
async fn an_authorization_older_than_the_offline_horizon_is_not_restored() {
    let device = Device::new();
    {
        let first = device.start();
        authorize(&first, PEER, PEER_KEY);
        authorize(&first, OTHER_PEER, OTHER_PEER_KEY);
    }
    // Age only one of the two, so the refusal below is a judgement about
    // that peer and not a restart that restores nobody.
    device.backdate_peer(
        PEER,
        super::offline_authorization::OFFLINE_AUTHORIZATION_HORIZON_SECS + 60 * 60,
    );

    let restarted = device.start();

    assert!(
        restarted.authority.is_authorized_lan_peer(&OTHER_PEER_KEY),
        "control: a recent authorization is still acted on"
    );
    assert!(
        !restarted.authority.is_authorized_lan_peer(&PEER_KEY),
        "an authorization older than the offline horizon must not be acted on"
    );
    assert!(
        restarted.authority.device_id_for_signing_key(&PEER_KEY).is_none(),
        "an expired authorization must not resolve its device either"
    );
}

/// The erasure's in-memory bookkeeping may not run ahead of its durable
/// write.
///
/// The cache reserves the membership generation a block ahead on disk so a
/// restart resumes above anything the previous run used. The reservation
/// is therefore a claim about what a transaction ACTUALLY wrote -- the
/// per-peer write paths only record it once the repository call returned
/// `Ok`. Recording it for a write that failed would leave the run believing
/// the ceiling had moved while the counter row still held the old number,
/// and every later write in the run would then skip carrying it, so the
/// restart would resume under a ceiling the run had already passed.
///
/// The failure is produced the only way the repository can fail on demand
/// here: the table the erasure deletes from is removed underneath it, so
/// the transaction rolls back with the counter row untouched. That is a
/// stand-in for a disk fault, not a case production reaches.
#[tokio::test]
async fn a_failed_erasure_does_not_advance_the_reserved_generation() {
    let device = Device::new();
    let state = device.start();
    assert_eq!(
        state.authority.offline_snapshot_reserved_generation(),
        0,
        "sanity check: a device that has written nothing has reserved nothing"
    );

    state
        .replica_coordinator
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute_batch("DROP TABLE offline_peer_authorization")
        .unwrap();

    // Best-effort by construction: a snapshot this device cannot write is
    // never a reason to fail the authorization change being mirrored, so
    // this returns normally and the failure shows up only in what it did
    // NOT record.
    state.forget_offline_peer_authorization();

    let on_disk = state
        .replica_coordinator
        .offline_peer_authorization_repository()
        .snapshot_versions()
        .expect("the counter row's own table is untouched")
        .membership_generation;
    assert_eq!(on_disk, 0, "sanity check: the rolled-back transaction advanced nothing on disk");
    assert_eq!(
        state.authority.offline_snapshot_reserved_generation(),
        on_disk,
        "the reservation states what disk already holds; a write that failed must leave it \
         where it was, exactly as the per-peer write paths do"
    );
}
