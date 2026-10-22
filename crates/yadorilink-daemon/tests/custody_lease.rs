//! Full-stack check of the durable custody lease: an on-demand device asks a
//! full replica to take custody of an exact version; the full replica commits
//! a lease row that is a block-GC live root before it acknowledges, and
//! refuses a requester it no longer authorizes.

mod support;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};
use yadorilink_sync_sqlite::MaterializationStateRepository;

const GROUP: &str = "lease-group";

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
}

fn new_daemon(device_id: &str) -> Daemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, _root: root }
}

fn index(daemon: &Daemon, path: &str, hash_bytes: &[u8], size: u64) {
    let record = FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash_bytes.to_vec(), offset: 0, size: size as u32 }],
        deleted: false,
    };
    daemon
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
}

fn put_and_record(daemon: &Daemon, data: &[u8]) -> Vec<u8> {
    let hash_hex = daemon.state.block_store.put(data).unwrap();
    let hash_bytes = hex::decode(&hash_hex).unwrap();
    daemon
        .state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&hash_bytes))
        .unwrap();
    hash_bytes
}

fn version_and_blocks(hash_bytes: Vec<u8>, size: u64) -> (VersionHash, Vec<VersionBlock>) {
    let blocks = vec![VersionBlock { hash: BlockHash(hash_bytes), size: size as u32 }];
    let meta = FileMeta {
        mtime_unix_nanos: 0,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    (FileVersion::new(blocks.clone(), size, meta).version_hash, blocks)
}

fn live_blocks(daemon: &Daemon) -> HashSet<String> {
    MaterializationStateRepository::new(daemon.state.replica_coordinator.database())
        .live_block_hashes_including_native_heads()
        .unwrap()
}

/// Both devices index `held.bin`; the full replica `a` holds its block.
async fn connected_pair() -> (Daemon, Daemon, Vec<u8>, VersionHash, Vec<VersionBlock>) {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");
    let content = b"content the complete copy takes custody of";
    let hash_bytes = put_and_record(&a, content);
    index(&a, "held.bin", &hash_bytes, content.len() as u64);
    index(&b, "held.bin", &hash_bytes, content.len() as u64);
    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (vh, blocks) = version_and_blocks(hash_bytes.clone(), content.len() as u64);
    (a, b, hash_bytes, vh, blocks)
}

/// `confirm_exact_version` is the durable acquire: when it returns a stamp the
/// responder already holds a committed lease for this requester, an identical
/// retry changes nothing, and the leased blocks stay a GC live root after the
/// responder's own rows for the path are gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmation_is_a_committed_lease_that_keeps_the_blocks_live() {
    let (a, b, hash_bytes, vh, blocks) = connected_pair().await;
    let leases = a.state.replica_coordinator.remote_custody_lease_repository();
    assert!(leases.list_active().unwrap().is_empty());

    assert!(b.state.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks));
    let active = leases.list_active().unwrap();
    assert_eq!(active.len(), 1, "the acknowledged acquire left a committed lease");
    assert_eq!(active[0].requester_device_id, "device-b");
    assert_eq!(active[0].version_hash, *vh.as_bytes());

    assert!(b.state.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks));
    assert_eq!(leases.list_active().unwrap(), active, "a retry is the same lease");

    // The responder's own roots for the path go away (retention expiry, a
    // delete): the lease alone keeps the block live.
    a.state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM files", [])?;
            Ok(())
        })
        .unwrap();
    assert!(live_blocks(&a).contains(&hex::encode(&hash_bytes)));

    // Only an explicit release ends it.
    let token = hold_token(&b, "device-a", &vh);
    assert!(b.state.release_custody_lease_via_peer("device-a", GROUP, "held.bin", vh, token).await);
    assert!(leases.list_active().unwrap().is_empty());
    assert!(!live_blocks(&a).contains(&hex::encode(&hash_bytes)));
}

/// A requester the responder no longer authorizes for the group cannot
/// acquire: no acknowledgement, no lease row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requester_the_responder_no_longer_authorizes_cannot_acquire() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    let (_, session_to_b) = a
        .state
        .peers
        .all_sessions()
        .into_iter()
        .find(|(peer, _)| peer == "device-b")
        .expect("a has a session with b");
    session_to_b.revoke_group(GROUP);

    assert!(!b.state.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks));
    assert!(a
        .state
        .replica_coordinator
        .remote_custody_lease_repository()
        .list_active()
        .unwrap()
        .is_empty());
}

/// A responder that does not hold the version (or holds different bytes)
/// never acknowledges, and writes no lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_the_responder_does_not_hold_leaves_no_lease() {
    let (a, b, _hash_bytes, _vh, _blocks) = connected_pair().await;
    let (wrong_vh, wrong_blocks) = version_and_blocks(vec![9u8; 32], 41);
    assert!(!b.state.full_replica_custody_confirmed(GROUP, "held.bin", &wrong_vh, &wrong_blocks));
    assert!(a
        .state
        .replica_coordinator
        .remote_custody_lease_repository()
        .list_active()
        .unwrap()
        .is_empty());
}

/// A GC sweep that has taken its live set holds the deletion guard until it is
/// done: an acquire arriving meanwhile must not commit or acknowledge before
/// then, or the sweep could delete the blocks it is about to vouch for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acquire_waits_out_a_running_block_deletion() {
    let (a, b, hash_bytes, vh, blocks) = connected_pair().await;
    let deletion = a.state.replica_coordinator.block_liveness_gate().begin_physical_deletion();
    let asker = b.state.clone();
    let task = tokio::spawn(async move {
        asker.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks)
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let leases = a.state.replica_coordinator.remote_custody_lease_repository();
    assert!(!task.is_finished(), "acknowledged while a sweep held the deletion guard");
    assert!(leases.list_active().unwrap().is_empty());

    drop(deletion);
    assert!(task.await.unwrap());
    assert_eq!(leases.list_active().unwrap().len(), 1);
    assert!(live_blocks(&a).contains(&hex::encode(&hash_bytes)));
}

/// The responder's exact-version proof (block reads, hashing, the lease commit)
/// is synchronous. While an acquire waits on it, the async runtime keeps
/// running: with a single worker, a timer task must keep ticking.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_waiting_acquire_does_not_stall_the_async_runtime() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    // A sweep, on a thread of its own, holds the deletion guard for a second.
    let coordinator = a.state.replica_coordinator.clone();
    let (taken, wait_taken) = std::sync::mpsc::channel();
    let release = std::thread::spawn(move || {
        let _deletion = coordinator.block_liveness_gate().begin_physical_deletion();
        taken.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(1000));
    });
    wait_taken.recv().unwrap();
    let asker = b.state.clone();
    let acquire = tokio::spawn(async move {
        asker.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks)
    });
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticker = {
        let ticks = ticks.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(700)).await;
    let during = ticks.load(std::sync::atomic::Ordering::SeqCst);
    assert!(!acquire.is_finished(), "acknowledged while a sweep held the deletion guard");
    ticker.abort();
    release.join().unwrap();
    assert!(acquire.await.unwrap());
    assert!(during >= 10, "the runtime ran {during} timer ticks in 700ms while an acquire waited");
}

/// Measurement, not a gate: how long the strong exact-version proof takes at
/// 4 KiB, 1 MiB and 1 GiB (4 MiB blocks), and whether the async runtime (one
/// worker) keeps running meanwhile. Run in release:
/// `cargo test --release -p yadorilink-daemon --test custody_lease custody_acquire_cost -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
#[ignore = "measurement; writes 1 GiB"]
async fn custody_acquire_cost() {
    support::ensure_isolated_config_dir();
    for (label, total, block) in [
        ("4 KiB", 4usize << 10, 4usize << 10),
        ("1 MiB", 1 << 20, 1 << 20),
        ("1 GiB", 1 << 30, 4 << 20),
    ] {
        let a = new_daemon("device-a");
        let b = new_daemon("device-b");
        let mut blocks = Vec::new();
        let mut infos = Vec::new();
        for n in 0..total / block {
            let mut data = vec![(n % 251) as u8; block];
            data[..8].copy_from_slice(&(n as u64).to_le_bytes());
            let hash = put_and_record(&a, &data);
            infos.push(BlockInfo {
                hash: hash.clone(),
                offset: (n * block) as u64,
                size: block as u32,
            });
            blocks.push(VersionBlock { hash: BlockHash(hash), size: block as u32 });
        }
        let record = FileRecord {
            path: "held.bin".into(),
            size: total as u64,
            mtime_unix_nanos: 0,
            blocks: infos.clone(),
            deleted: false,
        };
        for daemon in [&a, &b] {
            daemon
                .state
                .replica_coordinator
                .file_index_repository()
                .upsert_file(GROUP, &record, &RootCommitPermit::for_tests())
                .unwrap();
        }
        let meta = FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        };
        let vh = FileVersion::new(blocks.clone(), total as u64, meta).version_hash;
        connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
        b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
        b.state.install_p2p_custody_confirmer();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            })
        };
        let asker = b.state.clone();
        let started = std::time::Instant::now();
        let granted = tokio::spawn(async move {
            asker.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks)
        })
        .await
        .unwrap();
        let took = started.elapsed();
        ticker.abort();
        let ticks = ticks.load(std::sync::atomic::Ordering::SeqCst);
        eprintln!(
            "custody acquire {label}: granted={granted} {took:?}, {ticks} runtime ticks (10 ms \
             timer; {} expected if the runtime stayed free)",
            took.as_millis() / 10
        );
        assert!(granted);
    }
}

/// A requester removed from the group can still end the lease that pins the
/// responder's blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_requester_can_still_release_its_lease() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    assert!(b.state.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks));
    let (_, session_to_b) = a
        .state
        .peers
        .all_sessions()
        .into_iter()
        .find(|(peer, _)| peer == "device-b")
        .expect("a has a session with b");
    session_to_b.revoke_group(GROUP);

    let token = hold_token(&b, "device-a", &vh);
    assert!(b.state.release_custody_lease_via_peer("device-a", GROUP, "held.bin", vh, token).await);
    assert!(a
        .state
        .replica_coordinator
        .remote_custody_lease_repository()
        .list_active()
        .unwrap()
        .is_empty());
}

// ---- The requester's durable hold and the reconciler that ends it ----

use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::FullReplicaCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::remote_custody_hold::{HoldKey, HoldState};

const PATH: &str = "held.bin";

fn hold_key(peer: &str, vh: &VersionHash) -> HoldKey {
    HoldKey {
        group_id: GROUP.into(),
        path: PATH.into(),
        version_hash: *vh.as_bytes(),
        peer_id: peer.into(),
    }
}

fn hold_state(daemon: &Daemon, key: &HoldKey) -> Option<HoldState> {
    daemon
        .state
        .replica_coordinator
        .remote_custody_hold_repository()
        .get(key)
        .unwrap()
        .map(|hold| hold.state)
}

fn set_state(daemon: &Daemon, state: MaterializationState) {
    daemon
        .state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, PATH, state, &RootCommitPermit::for_tests())
        .unwrap();
}

fn hold_token(daemon: &Daemon, peer: &str, vh: &VersionHash) -> [u8; 16] {
    daemon
        .state
        .replica_coordinator
        .remote_custody_hold_repository()
        .get(&hold_key(peer, vh))
        .unwrap()
        .expect("a hold row")
        .attempt_token
}

fn lease_count(daemon: &Daemon) -> usize {
    daemon.state.replica_coordinator.remote_custody_lease_repository().list_active().unwrap().len()
}

/// End to end, the requester's row is `requested` while the acquire is
/// outstanding at the responder (held at its deletion guard) and `granted`
/// once it is acknowledged. That the row is committed *before* the RPC is sent
/// is pinned by the unit test that reads it from inside the send
/// (`custody_holds::tests`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_requested_row_exists_when_the_acquire_arrives() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    let deletion = a.state.replica_coordinator.block_liveness_gate().begin_physical_deletion();
    let asker = b.state.clone();
    let task = tokio::spawn(async move {
        asker.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await
    });
    let key = hold_key("device-a", &vh);
    support::wait_until(
        || hold_state(&b, &key) == Some(HoldState::Requested),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(lease_count(&a), 0, "the responder had not committed yet");

    drop(deletion);
    let stamp = task.await.unwrap().expect("the responder acknowledged");
    assert_eq!(stamp.peer_id(), "device-a");
    assert_eq!(hold_state(&b, &key), Some(HoldState::Granted), "granted before the stamp returned");
    assert_eq!(lease_count(&a), 1);
}

/// A stamp is only valid while its hold is recorded as granted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stamp_is_valid_only_while_its_hold_is_granted() {
    let (_a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    let stamp = b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
    assert!(b.state.confirmation_still_valid(GROUP, PATH, &vh, &stamp));

    let holds = b.state.replica_coordinator.remote_custody_hold_repository();
    holds.delete(&hold_key("device-a", &vh)).unwrap();
    assert!(!b.state.confirmation_still_valid(GROUP, PATH, &vh, &stamp), "no row");
    holds
        .record_requested(&hold_key("device-a", &vh), stamp.membership_generation(), [1; 16])
        .unwrap();
    assert!(!b.state.confirmation_still_valid(GROUP, PATH, &vh, &stamp), "requested, not granted");
}

/// Crash after the responder committed but before the requester saw the ACK,
/// and crash after the INSERT before the RPC: the `requested` row is released
/// at the next pass whether or not a lease exists, and then removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requested_row_is_released_and_removed_after_a_restart() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    set_state(&b, MaterializationState::Present);
    let holds = b.state.replica_coordinator.remote_custody_hold_repository();

    // Responder committed, ACK lost: the lease exists, the requester has only `requested`.
    assert!(b.state.full_replica_custody_confirmed(GROUP, PATH, &vh, &blocks));
    assert_eq!(lease_count(&a), 1);
    let sent_token = hold_token(&b, "device-a", &vh);
    holds.delete(&hold_key("device-a", &vh)).unwrap();
    holds.record_requested(&hold_key("device-a", &vh), 1, sent_token).unwrap();
    // And a second version whose RPC never left: a row, no lease.
    let never_sent = VersionHash([5u8; 32]);
    holds.record_requested(&hold_key("device-a", &never_sent), 1, [2; 16]).unwrap();

    b.state.release_obsolete_custody_holds().await;

    assert_eq!(lease_count(&a), 0, "the committed lease was released");
    assert!(holds.list().unwrap().is_empty(), "both rows are gone");
}

/// Acquired, then the eviction never started or aborted (path dirty, busy,
/// revalidation failed): the file is still `Present`, so the grant is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aborted_eviction_releases_its_granted_lease() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    set_state(&b, MaterializationState::Present);
    b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
    assert_eq!(lease_count(&a), 1);

    b.state.release_obsolete_custody_holds().await;

    assert_eq!(lease_count(&a), 0);
    assert_eq!(hold_state(&b, &hold_key("device-a", &vh)), None);
}

/// A completed eviction (`Remote`) at the held version keeps its lease, and an
/// `Evicting` row (resolved by the startup reset before the reconciler runs, or
/// still in flight) is never released out from under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_or_evicting_row_at_the_held_version_keeps_its_lease() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
    for state in [MaterializationState::Evicting, MaterializationState::Remote] {
        set_state(&b, state);
        b.state.release_obsolete_custody_holds().await;
        assert_eq!(lease_count(&a), 1, "{state:?} keeps the lease");
        assert_eq!(hold_state(&b, &hold_key("device-a", &vh)), Some(HoldState::Granted));
    }
}

/// Rehydrated, a newer version, or deleted: the granted lease is obsolete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rehydrate_a_newer_version_and_a_delete_each_release_the_lease() {
    for change in ["rehydrate", "newer", "deleted"] {
        let (a, b, hash_bytes, vh, blocks) = connected_pair().await;
        b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
        set_state(&b, MaterializationState::Remote);
        b.state.release_obsolete_custody_holds().await;
        assert_eq!(lease_count(&a), 1, "{change}: remote at the held version is kept");

        match change {
            "rehydrate" => set_state(&b, MaterializationState::Present),
            "newer" => index(&b, PATH, &[3u8; 32], 7),
            _ => b
                .state
                .replica_coordinator
                .file_index_repository()
                .upsert_file(
                    GROUP,
                    &FileRecord {
                        path: PATH.to_string(),
                        size: 0,
                        mtime_unix_nanos: 0,
                        blocks: vec![BlockInfo { hash: hash_bytes, offset: 0, size: 41 }],
                        deleted: true,
                    },
                    &RootCommitPermit::for_tests(),
                )
                .unwrap(),
        }
        b.state.release_obsolete_custody_holds().await;
        assert_eq!(lease_count(&a), 0, "{change}: released");
        assert!(b
            .state
            .replica_coordinator
            .remote_custody_hold_repository()
            .list()
            .unwrap()
            .is_empty());
    }
}

/// The responder is unreachable: nothing can be released, the row stays, and
/// it is released once the peer is reachable again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_peer_keeps_the_row() {
    let (_a, b, _hash_bytes, vh, _blocks) = connected_pair().await;
    set_state(&b, MaterializationState::Present);
    let offline = hold_key("device-offline", &vh);
    let holds = b.state.replica_coordinator.remote_custody_hold_repository();
    holds.record_requested(&offline, 1, [3; 16]).unwrap();

    b.state.release_obsolete_custody_holds().await;

    assert_eq!(hold_state(&b, &offline), Some(HoldState::Requested));
}

/// The reconciler skips a path whose lock is held (an eviction in flight): the
/// eviction's stamp stays backed by a live lease. Once the path settles the
/// next pass releases it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reconciler_skips_a_path_an_eviction_holds_locked() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    set_state(&b, MaterializationState::Present);
    let lock = b.state.replica_coordinator.path_lock(GROUP, PATH);
    let in_flight_eviction = lock.lock().await;
    let stamp = b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();

    b.state.release_obsolete_custody_holds().await;
    assert_eq!(lease_count(&a), 1, "the in-flight eviction's lease is untouched");
    assert!(b.state.confirmation_still_valid(GROUP, PATH, &vh, &stamp));

    drop(in_flight_eviction);
    b.state.release_obsolete_custody_holds().await;
    assert_eq!(lease_count(&a), 0);
}

/// The long-running reconciler task is woken by a nudge (an eviction that
/// settled) and releases what the settled path no longer needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nudged_reconciler_task_releases_the_lease() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    set_state(&b, MaterializationState::Present);
    let task = yadorilink_daemon::custody_holds::spawn_custody_hold_reconciler(&b.state);
    // The acquire contract: the caller holds the path lock, so the running reconciler cannot
    // release the requested hold before the peer has answered.
    let lock = b.state.replica_coordinator.path_lock(GROUP, PATH);
    let held = lock.lock().await;
    b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
    drop(held);
    b.state.nudge_custody_hold_reconciler();
    support::wait_until(|| lease_count(&a) == 0, Duration::from_secs(5)).await;
    task.abort();
}

// ---- Attempt tokens, and leases when the responder's role changes ----

fn session_to(
    daemon: &Daemon,
    peer: &str,
) -> Arc<yadorilink_peer_session::peer_session::PeerSyncSession> {
    daemon
        .state
        .peers
        .all_sessions()
        .into_iter()
        .find(|(id, _)| id == peer)
        .map(|(_, session)| session)
        .unwrap_or_else(|| panic!("no session to {peer}"))
}

/// A release that reaches the responder before the acquire it answers (the
/// acquire timed out at the requester, which then gave the attempt up) makes
/// that acquire, arriving late, commit nothing -- and so leaves no lease for
/// anyone to remember to release. A later attempt is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_acquire_after_its_release_commits_nothing() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    let session = session_to(&b, "device-a");
    let epoch = b.state.authority.membership_generation();
    let attempt = [0x11u8; 16];

    assert!(
        session.request_custody_release(GROUP, PATH, vh, attempt).await,
        "a release for an attempt the responder never saw is still acknowledged"
    );
    assert!(
        !session.request_custody_acquire(GROUP, PATH, vh, &blocks, epoch, attempt).await,
        "the late acquire of the released attempt is refused"
    );
    assert_eq!(lease_count(&a), 0);

    assert!(session.request_custody_acquire(GROUP, PATH, vh, &blocks, epoch, [0x22; 16]).await);
    assert_eq!(lease_count(&a), 1, "the next attempt commits normally");
}

/// A duplicate release of an attempt the requester has since replaced ends
/// nothing: only the release naming the attempt that holds the lease does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_of_another_attempt_leaves_the_lease_in_place() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    let session = session_to(&b, "device-a");
    let epoch = b.state.authority.membership_generation();
    assert!(session.request_custody_acquire(GROUP, PATH, vh, &blocks, epoch, [1; 16]).await);

    assert!(session.request_custody_release(GROUP, PATH, vh, [2; 16]).await);
    assert_eq!(lease_count(&a), 1, "an unrelated attempt's release does not end it");

    assert!(session.request_custody_release(GROUP, PATH, vh, [1; 16]).await);
    assert_eq!(lease_count(&a), 0);
}

/// A requester presenting an older membership generation while still authorized
/// still acquires: the generation is recorded, not compared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authorized_requester_with_an_older_generation_still_acquires() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    let session = session_to(&b, "device-a");
    let epoch = b.state.authority.membership_generation();
    assert!(session.request_custody_acquire(GROUP, PATH, vh, &blocks, 0, [1; 16]).await);
    let leases =
        a.state.replica_coordinator.remote_custody_lease_repository().list_active().unwrap();
    assert_eq!(leases[0].membership_generation, 0);
    assert!(epoch > 0, "the requester's own generation has moved on");
}

/// Three devices: `a` and `c` are full replicas holding the file, `b` is the
/// on-demand requester. `b` holds a granted custody lease at `a` and has
/// evicted the file.
async fn trio_with_lease_at_a() -> (Daemon, Daemon, Daemon, VersionHash, Vec<VersionBlock>) {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");
    let c = new_daemon("device-c");
    let content = b"content the complete copy takes custody of";
    let hash_bytes = put_and_record(&a, content);
    assert_eq!(put_and_record(&c, content), hash_bytes);
    for full in [&a, &c, &b] {
        index(full, PATH, &hash_bytes, content.len() as u64);
    }
    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    connect_two_daemons(&c.state, "device-c", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (vh, blocks) = version_and_blocks(hash_bytes, content.len() as u64);

    // Only `a` is a full replica while `b` acquires, so the lease lands there.
    let stamp = b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await;
    assert_eq!(stamp.expect("a stamp").peer_id(), "device-a");
    set_state(&b, MaterializationState::Remote);
    assert_eq!((lease_count(&a), lease_count(&c)), (1, 0));
    b.state.authority.set_peer_group_full_replica("device-c", GROUP, true);
    (a, b, c, vh, blocks)
}

/// A responder giving up its role with another full replica available: the
/// requester takes custody at the other one and releases the first, and only
/// then does the hand-off return. Afterwards the lease lives at the new
/// responder, the requester has a granted hold there and none at the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_responder_giving_up_its_role_hands_its_lease_to_another_full_replica() {
    let (a, b, c, vh, _blocks) = trio_with_lease_at_a().await;

    let closed = a.state.hand_off_custody_leases(GROUP).await.expect("the lease can move");

    assert_eq!((lease_count(&a), lease_count(&c)), (0, 1));
    assert_eq!(
        hold_state(&b, &hold_key("device-a", &vh)),
        None,
        "no hold left at the old responder"
    );
    assert_eq!(hold_state(&b, &hold_key("device-c", &vh)), Some(HoldState::Granted));
    let moved =
        c.state.replica_coordinator.remote_custody_lease_repository().list_active().unwrap();
    assert_eq!(moved[0].requester_device_id, "device-b");
    assert_eq!(moved[0].version_hash, *vh.as_bytes(), "the exact version, not the current one");
    assert_eq!(
        moved[0].attempt_token,
        b.state
            .replica_coordinator
            .remote_custody_hold_repository()
            .get(&hold_key("device-c", &vh))
            .unwrap()
            .unwrap()
            .attempt_token,
        "the new lease is held by the attempt the requester's new hold names"
    );
    drop(closed);
}

/// While the hand-off guard is held the old responder takes no new lease; the
/// retry of a refused acquire succeeds once the guard is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_being_handed_off_takes_no_new_lease_until_the_guard_drops() {
    let (a, b, _c, vh, blocks) = trio_with_lease_at_a().await;
    let closed = a.state.hand_off_custody_leases(GROUP).await.unwrap();
    let session = session_to(&b, "device-a");
    let epoch = b.state.authority.membership_generation();

    assert!(!session.request_custody_acquire(GROUP, PATH, vh, &blocks, epoch, [5; 16]).await);
    assert_eq!(lease_count(&a), 0);

    drop(closed);
    assert!(session.request_custody_acquire(GROUP, PATH, vh, &blocks, epoch, [5; 16]).await);
    assert_eq!(lease_count(&a), 1);
}

/// With nowhere to move the lease the hand-off fails, the lease and the
/// requester's hold stay exactly as they were, and the responder takes leases
/// again: the operation is simply retried later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_no_other_full_replica_the_hand_off_fails_and_changes_nothing() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
    set_state(&b, MaterializationState::Remote);
    let before =
        a.state.replica_coordinator.remote_custody_lease_repository().list_active().unwrap();

    let error = a.state.hand_off_custody_leases(GROUP).await.err().expect("must refuse");

    assert!(error.contains("device-b"), "{error}");
    assert_eq!(
        a.state.replica_coordinator.remote_custody_lease_repository().list_active().unwrap(),
        before
    );
    assert_eq!(hold_state(&b, &hold_key("device-a", &vh)), Some(HoldState::Granted));
    assert!(
        b.state.full_replica_custody_confirmed(GROUP, PATH, &vh, &blocks),
        "the responder takes (and re-acknowledges) leases again"
    );
}

/// A requester that is not connected cannot be asked to move: the hand-off
/// fails rather than guessing that nothing depends on the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requester_that_cannot_be_reached_blocks_the_hand_off() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();
    a.state.peers.remove("device-b");

    assert!(a.state.hand_off_custody_leases(GROUP).await.is_err());
    assert_eq!(lease_count(&a), 1);
}

/// A crash after the requester took custody at the new responder but before it
/// released the old one leaves a granted hold at each. Asking again finishes
/// the move without creating a second lease at the new responder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_off_interrupted_after_the_new_lease_is_finished_by_asking_again() {
    let (a, b, c, vh, blocks) = trio_with_lease_at_a().await;
    // The requester's second hold and the new responder's lease, as left by a
    // crash between the acquire at `c` and the release at `a`.
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, false);
    let stamp = b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await;
    assert_eq!(stamp.expect("a stamp").peer_id(), "device-c");
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    assert_eq!(lease_count(&c), 1);
    assert_eq!(lease_count(&a), 1);

    a.state.hand_off_custody_leases(GROUP).await.expect("finishes the move");

    assert_eq!((lease_count(&a), lease_count(&c)), (0, 1));
    assert_eq!(hold_state(&b, &hold_key("device-a", &vh)), None);
    assert_eq!(hold_state(&b, &hold_key("device-c", &vh)), Some(HoldState::Granted));
}

/// A requester whose placeholder no longer depends on the lease (the file was
/// rehydrated) just releases it: no new custody anywhere, and the hand-off
/// succeeds even with no other full replica.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_nothing_depends_on_is_released_by_the_hand_off() {
    let (a, b, _hash_bytes, vh, blocks) = connected_pair().await;
    set_state(&b, MaterializationState::Present);
    b.state.acquire_custody_lease_via_peer(GROUP, PATH, vh, &blocks).await.unwrap();

    a.state.hand_off_custody_leases(GROUP).await.expect("nothing to keep");

    assert_eq!(lease_count(&a), 0);
    assert_eq!(hold_state(&b, &hold_key("device-a", &vh)), None);
}

/// A requester already at its lease budget is refused a new lease through the
/// real acquire path: the answer is "not held" (so the requester keeps its
/// blocks, see `provider_evict`), no lease is added and existing ones stay.
/// Re-confirming a lease it already holds still succeeds at the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_requester_at_the_lease_cap_is_refused_a_new_lease_but_keeps_existing_ones() {
    use yadorilink_sync_sqlite::remote_custody_lease::{
        CustodyLeaseRequest, MAX_ACTIVE_LEASES_PER_REQUESTER,
    };
    let (a, b, hash_bytes, vh, blocks) = connected_pair().await;
    assert!(b.state.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks));
    let leases = a.state.replica_coordinator.remote_custody_lease_repository();
    for n in 1..MAX_ACTIVE_LEASES_PER_REQUESTER {
        let request = CustodyLeaseRequest {
            group_id: GROUP.into(),
            requester_device_id: "device-b".into(),
            path: format!("filler-{n}.bin"),
            version_hash: [7; 32],
            blocks: vec![hex::encode(&hash_bytes)],
            membership_generation: 0,
            attempt_token: [7; 16],
            now_unix: 0,
        };
        assert!(leases.acquire(&request).unwrap().was_created());
    }
    assert_eq!(leases.list_active().unwrap().len(), MAX_ACTIVE_LEASES_PER_REQUESTER);

    index(&a, "second.bin", &hash_bytes, 41);
    index(&b, "second.bin", &hash_bytes, 41);
    assert!(!b.state.full_replica_custody_confirmed(GROUP, "second.bin", &vh, &blocks));
    assert_eq!(leases.list_active().unwrap().len(), MAX_ACTIVE_LEASES_PER_REQUESTER);

    assert!(b.state.full_replica_custody_confirmed(GROUP, "held.bin", &vh, &blocks));
    assert_eq!(leases.list_active().unwrap().len(), MAX_ACTIVE_LEASES_PER_REQUESTER);
    assert!(live_blocks(&a).contains(&hex::encode(&hash_bytes)));
}
