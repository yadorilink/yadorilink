//! R3b-1: focused regression for a partial-hydration-progress bug found
//! while debugging `topology_simultaneous_reconnect_and_relay_hydration_
//! failure.rs`'s relay-recovery step. Each block, once fetched, is
//! individually verified and durably written to the block store — but
//! (before this file's fix) this group's *provenance* for it was only
//! recorded in one batch after the WHOLE multi-block dispatch returned.
//! `hydrate`'s outer `tokio::time::timeout` (`hydrate_with_timeout`) drops
//! that whole dispatch future the instant its deadline fires, so a
//! still-in-flight attempt could durably persist several blocks' bytes and
//! then never reach the batched provenance commit for any of them. The
//! next hydration attempt's `resolve_blocks_local_first` treats a present-
//! but-unprovenanced block as still missing (`has_group_provenance` gates
//! `already_present`), so those bytes were silently re-fetched from
//! scratch every retry — this is what made the relay-recovery scenario
//! transfer ~80% of a 6MB payload on every single attempt without ever
//! converging.
//!
//! Deliberately lightweight, hand-built peer sessions over a direct
//! loopback pairing — like `multi_peer_hydration.rs` — rather than the
//! full coordination-plane harness, so the test can deterministically keep
//! a fetch genuinely in flight past the outer deadline (via
//! `SlowBlockStore`) instead of racing real transfer speed with a poll
//! loop.

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{
    BlockStore, ContentHash, GcReport, SegmentBlockStore, StorageError, DEFAULT_BLOCK_SIZE,
};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;

/// Wraps a real `SegmentBlockStore` and adds a fixed delay before every `get` --
/// used to make one test device's block-serve responses arrive well past
/// this suite's outer hydrate deadline (never within `PER_BLOCK_FETCH_
/// TIMEOUT` either), so a fetch through it stays genuinely "still trying"
/// for as long as the test needs, deterministically, instead of racing
/// real transfer speed with a poll loop or relying on how a severed
/// connection happens to fail (observed directly: a closed peer connection
/// makes `fetch_block` return fast, which reads to the dispatcher exactly
/// like an explicit not-found reply and lets the block get marked
/// exhausted almost immediately -- not the "connection genuinely still
/// alive but stalled" condition this regression needs).
struct SlowBlockStore {
    inner: Arc<SegmentBlockStore>,
    delay: Duration,
}

impl BlockStore for SlowBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        std::thread::sleep(self.delay);
        self.inner.get(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }
}

const GROUP: &str = "shared";
const PATH: &str = "big.bin";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_root: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

fn new_device(device_id: &str) -> TestDevice {
    let store_root = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_root.path()).unwrap());
    new_device_with_store(device_id, store_root, store)
}

/// Like [`new_device`], but lets the caller wrap the real `SegmentBlockStore` in
/// a decorator (e.g. [`SlowBlockStore`]) before it becomes this device's
/// `state.block_store` -- the same store `BlockServeEngine` reads from to
/// answer an incoming peer's block requests, so wrapping it here is what
/// makes this device slow (or otherwise abnormal) to SERVE from.
fn new_device_with_store(
    device_id: &str,
    store_root: tempfile::TempDir,
    store: Arc<dyn BlockStore + Send + Sync>,
) -> TestDevice {
    let index_dir = tempfile::tempdir().unwrap();
    let sync_state = Arc::new(ReplicaCoordinator::open(index_dir.path().join("index.db")).unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDevice {
        device_id: device_id.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        _store_root: store_root,
        _index_dir: index_dir,
    }
}

fn chunk_content(content: &[u8]) -> (Vec<BlockInfo>, HashMap<Vec<u8>, Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(dir.path()).unwrap();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, content).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(&store, &src).unwrap();
    let mut data_by_hash = HashMap::new();
    for block in &blocks {
        let hash_hex = hex::encode(&block.hash);
        data_by_hash.insert(block.hash.clone(), store.get(&hash_hex).unwrap());
    }
    (blocks, data_by_hash)
}

/// Same shape as `multi_peer_hydration.rs`'s own `seed_placeholder` — see
/// that file's copy for why each of these steps is required.
/// Seeds a peer that will ANSWER block requests: [`seed_placeholder`] plus
/// a real signed local Change for the file, driven to Published.
///
/// Block-serving authorization serves only blocks backed by a Published
/// Change (`published_group_file_version_references_block` joins against
/// `change_authorization`), which a bare `upsert_file` cannot satisfy. A
/// peer seeded the raw way holds the bytes and still refuses every request
/// with `reason="not_referenced"` -- measured here before this existed:
///
/// ```text
/// live_record_exists=true  live_record_references_hash=true
/// group_has_block_provenance=Ok(true)  store_get_ok=true
/// dag_group_file_version_references_block=Ok(false)
/// ```
///
/// `multi_peer_hydration.rs` carries the twin of this helper; each
/// full-stack test file in this crate keeps its own scaffolding by
/// established convention rather than sharing it, and the two files' device
/// fixtures differ (this one wraps a `SlowBlockStore`).
///
/// The physical holdings stay exactly as the caller asked: the Published
/// version references every block, while only `owned_blocks` are stored, so
/// "authorized to serve, does not hold it" remains expressible.
async fn seed_published_serving_placeholder(
    device: &TestDevice,
    blocks: &[BlockInfo],
    total_size: u64,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    seed_placeholder(device, blocks, total_size, owned_blocks, data_by_hash);
    let version = yadorilink_replica_domain::file::FileVersion::new(
        blocks
            .iter()
            .map(|b| yadorilink_replica_domain::file::VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(b.hash.clone()),
                size: b.size,
            })
            .collect(),
        total_size,
        yadorilink_replica_domain::file::FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: yadorilink_replica_domain::file::RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let record = FileRecord {
        path: PATH.to_string(),
        size: total_size,
        mtime_unix_nanos: 0,
        blocks: blocks.to_vec(),
        deleted: false,
    };
    let signing_key = device
        .state
        .device_signing_key()
        .expect("the checkpoint authority assigns every device a signing key");
    let emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
        &device.state.replica_coordinator,
        &device.device_id,
        signing_key,
    )
    .unwrap();
    yadorilink_daemon::test_support::local_seam::commit_local_upsert(
        &device.state.replica_coordinator,
        GROUP,
        &record,
        &device.device_id,
        &version,
        None,
        &emitter,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    // Pending is not servable, and this fixture runs neither of production's
    // flush triggers (a new local mutation's broadcast, or a reconnect).
    device.state.flush_pending_checkpoint_for_group_for_test(GROUP).await;
}

fn seed_placeholder(
    device: &TestDevice,
    blocks: &[BlockInfo],
    total_size: u64,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        device.root.path(),
        GROUP,
        device.state.replica_coordinator.as_ref(),
    )
    .unwrap();
    device.state.install_test_root_commit_authority(GROUP);

    let record = FileRecord {
        path: PATH.to_string(),
        size: total_size,
        mtime_unix_nanos: 0,
        blocks: blocks.to_vec(),
        deleted: false,
    };
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    device
        .state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Remote,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    device
        .state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(
            &local_path,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();
    give_blocks(device, owned_blocks, data_by_hash);
}

/// Durably persists `owned_blocks` into `device`'s block store and records
/// this group's provenance for each -- the same pairing the real block-
/// fetch dispatcher performs per block (`record_group_block_provenance`'s
/// doc comment: never claim provenance from metadata alone, only from
/// actually-obtained verified bytes). Split out from `seed_placeholder` so
/// a test can hand a device MORE blocks after its placeholder/link setup
/// already ran, without redoing that setup.
fn give_blocks(
    device: &TestDevice,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    for block in owned_blocks {
        device.state.block_store.put(&data_by_hash[&block.hash]).unwrap();
        device
            .state
            .replica_coordinator
            .record_block_provenance(GROUP, std::slice::from_ref(&block.hash))
            .unwrap();
    }
}

/// Like `multi_peer_hydration.rs`'s `connect_as_peer`.
async fn connect_as_peer(hydrating: &TestDevice, peer: &TestDevice) {
    let book = yadorilink_lane_ports::testing::TestAddressBook::new();
    let node_hydrating =
        yadorilink_lane_ports::testing::TestPeerNode::start(&hydrating.device_id, book.clone())
            .await;
    let node_peer =
        yadorilink_lane_ports::testing::TestPeerNode::start(&peer.device_id, book).await;
    let transports_to_peer = node_hydrating.transports_for(&peer.device_id);
    let transports_from_hydrating = node_peer.transports_for(&hydrating.device_id);
    let hydrating_peer_store =
        Arc::new(yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            hydrating.state.block_store.clone(),
        ));
    let replica_engine_to_peer =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &hydrating.state.replica_coordinator,
            hydrating_peer_store.clone(),
        );
    let session_to_peer = PeerSyncSession::over_substrate(
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_to_peer,
        hydrating_peer_store,
        vec![GROUP.to_string()],
        yadorilink_peer_session::ports::SessionTransports {
            blocks: transports_to_peer.clone(),
            service: transports_to_peer.clone(),
        },
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    session_to_peer.set_block_serve_engine(hydrating.state.block_serve_engine.clone());
    node_hydrating.serve_with(&peer.device_id, session_to_peer.clone());
    hydrating.state.peers.register_session(
        peer.device_id.clone(),
        session_to_peer,
        hydrating.state.local_convergence(),
    );

    let peer_peer_store =
        Arc::new(yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            peer.state.block_store.clone(),
        ));
    let replica_engine_from_hydrating =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &peer.state.replica_coordinator,
            peer_peer_store.clone(),
        );
    let session_from_hydrating = PeerSyncSession::over_substrate(
        peer.device_id.clone(),
        hydrating.device_id.clone(),
        peer.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_from_hydrating,
        peer_peer_store,
        vec![GROUP.to_string()],
        yadorilink_peer_session::ports::SessionTransports {
            blocks: transports_from_hydrating.clone(),
            service: transports_from_hydrating.clone(),
        },
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    session_from_hydrating.set_block_serve_engine(peer.state.block_serve_engine.clone());
    node_peer.serve_with(&hydrating.device_id, session_from_hydrating.clone());
}

fn ramp_content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The whole-file outer timeout dropping `hydrate_inner` mid-dispatch must
/// not lose provenance for blocks already durably fetched: every block
/// present in the block store after the timeout must also have this
/// group's provenance recorded for it (the exact condition `resolve_
/// blocks_local_first`'s next attempt reads), and a subsequent hydrate
/// with the connection restored must still converge to byte-exact content.
///
/// Deterministic by construction, not by racing real transfer speed
/// against a poll loop: two candidate sessions are wired up for the
/// target, `fast` (genuinely holds only a small owned prefix of the
/// blocks, served at normal speed) and `slow` (holds every other block,
/// but every `get` against its block store sleeps far longer than both
/// `PER_BLOCK_FETCH_TIMEOUT` and this test's own outer deadline). Blocks
/// in the owned prefix resolve quickly via `fast`; every other block is
/// still sitting in a live, in-flight fetch against `slow` -- not a clean
/// not-found, not a dead connection -- when the outer deadline fires,
/// exactly reproducing the real relay scenario's failure mode (a transfer
/// genuinely still moving bytes when its deadline hits) without depending
/// on wall-clock racing to catch it.
///
/// (`slow` explicitly does NOT mean "connection severed": that was tried
/// first and found not to reproduce this bug at all -- a closed
/// peer connection makes `fetch_block` return fast, which the dispatcher
/// cannot distinguish from an explicit not-found reply, so the block gets
/// marked exhausted almost immediately and `fetch_blocks_from_sessions`
/// returns normally well inside the deadline -- the exact case the OLD
/// code already handled correctly, since its batched provenance commit
/// still runs whenever the dispatch returns on its own.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_hydration_progress_survives_an_outer_timeout() {
    // `hydrate_with_timeout`'s deadline is no longer a flat wall-clock
    // ceiling (`HydrationStallTracker`/`per_block_fetch_timeout`): the
    // caller-supplied `OUTER_TIMEOUT` below is only a FLOOR, raised once
    // the actual missing blocks' sizes are known to `2 * PeerSyncSession::
    // fetch_response_timeout_for(max_missing_size) + STALL_BUDGET_MARGIN`
    // -- for `DEFAULT_BLOCK_SIZE`-ish blocks that's tens of seconds, not
    // `OUTER_TIMEOUT`'s own 3s. `SLOW_DELAY` must comfortably exceed the
    // per-block deadline itself (`fetch_response_timeout_for`'s own value
    // for this block size), not just `OUTER_TIMEOUT`, or `slow` simply
    // answers before its own per-block wait expires and the block
    // succeeds (slowly) instead of genuinely stalling -- confirmed
    // directly: this test regressed exactly that way when the size-aware
    // deadline was first introduced, with `slow`'s old 8s delay comfortably
    // inside the new ~21s per-128KiB-block deadline.
    const SLOW_DELAY: Duration = Duration::from_secs(30);
    const OUTER_TIMEOUT: Duration = Duration::from_secs(3);

    let content = ramp_content(DEFAULT_BLOCK_SIZE * 8);
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 4, "test needs several blocks to split a prefix off meaningfully");
    let owned_prefix = &blocks[..2];
    let hashes: Vec<String> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();

    let fast = new_device("device-fast");
    let slow = {
        let store_root = tempfile::tempdir().unwrap();
        let inner = Arc::new(SegmentBlockStore::new(store_root.path()).unwrap());
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(SlowBlockStore { inner, delay: SLOW_DELAY });
        new_device_with_store("device-slow", store_root, store)
    };
    let target = new_device("device-target");
    // One authority for the whole test: `coordination_client_config` is a
    // `OnceLock`, so devices cannot be reassigned to another fake later.
    let _authority = support::shared_checkpoint_authority(
        &[
            ("device-fast", &fast.state),
            ("device-slow", &slow.state),
            ("device-target", &target.state),
        ],
        &[GROUP.to_string()],
    )
    .await;

    // `fast` and `slow` answer block requests, so their holdings must be
    // backed by a Published Change. `target` only requests.
    seed_published_serving_placeholder(
        &fast,
        &blocks,
        content.len() as u64,
        owned_prefix,
        &data_by_hash,
    )
    .await;
    seed_published_serving_placeholder(
        &slow,
        &blocks,
        content.len() as u64,
        &blocks[2..],
        &data_by_hash,
    )
    .await;
    seed_placeholder(&target, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(&target, &fast).await;
    connect_as_peer(&target, &slow).await;

    let result = hydration::hydrate_with_timeout(&target.state, GROUP, PATH, OUTER_TIMEOUT).await;
    assert!(
        result.is_err(),
        "hydrate must fail: most blocks are still genuinely in flight against `slow` when the \
         outer deadline fires"
    );

    // The core fix under test: every block durably in the store must also
    // have this group's provenance recorded, matching exactly the
    // condition `resolve_blocks_local_first` checks on the next attempt.
    let present = target.state.block_store.present_blocks(&hashes).unwrap();
    for (block, is_present) in blocks.iter().zip(present.iter()) {
        let has_provenance = target
            .state
            .replica_coordinator
            .sqlite()
            .dag_group_has_block_provenance(GROUP, &block.hash)
            .unwrap();
        assert_eq!(
            *is_present,
            has_provenance,
            "block {} present={is_present} but has_provenance={has_provenance} -- a block \
             durably in the block store must also have this group's provenance recorded for \
             it, or the next hydration attempt will wrongly re-fetch it from scratch",
            hex::encode(&block.hash)
        );
    }
    assert!(
        owned_prefix.iter().all(|b| present[blocks.iter().position(|x| x.hash == b.hash).unwrap()]),
        "the owned-prefix blocks (reachable via `fast`) must have been fetched before the \
         timeout despite the rest of the file being permanently unreachable"
    );

    // Reconnect a peer that holds everything and confirm a retried hydrate
    // still converges to byte-exact content, proving the failure was a
    // clean, recoverable rejection.
    give_blocks(&fast, &blocks, &data_by_hash);
    connect_as_peer(&target, &fast).await;
    hydration::hydrate(&target.state, GROUP, PATH).await.unwrap();
    let reconstructed = std::fs::read(target.root.path().join(PATH)).unwrap();
    assert_eq!(
        reconstructed, content,
        "the retried hydrate's recovered content must be byte-exact"
    );
}
