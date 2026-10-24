//! parallel-multi-peer-fetch real, connected-session integration tests for
//! `yadorilink_daemon::hydration`'s multi-session block dispatch.

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_daemon::change_policy::{GroupPolicyState, WriterRole};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_daemon::rewind;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore, DEFAULT_BLOCK_SIZE};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{
    BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
};
use yadorilink_replica_domain::ids::BlockHash;
use yadorilink_replica_domain::rewind::RewindRunState;
use yadorilink_replica_domain::session_state::MaterializationState;

const GROUP: &str = "shared";
const PATH: &str = "big.bin";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    store_root: tempfile::TempDir,
    // Keeps the file-backed index database alive for the device's lifetime
    // (see `new_device` on why this is not `open_in_memory`).
    _index_dir: tempfile::TempDir,
}

fn new_device(device_id: &str) -> TestDevice {
    let store_root = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_root.path()).unwrap());
    // File-backed WAL, not `open_in_memory`: the shared-cache in-memory
    // backend takes TABLE-level locks, so a background reader on another
    // pooled connection (the daemon tasks `DaemonState::new` spawns) makes a
    // concurrent writer fail with `SQLITE_LOCKED_SHAREDCACHE` — observed as
    // a CI-only flake ("database table is locked: links" out of
    // `seed_placeholder`'s `add_link` on a slow runner, past the bounded
    // lock-retry window). Production runs file-backed WAL, where readers
    // never block the writer like this; `monkey_chaos.rs` made the same
    // switch for the same reason (`open_file_backed_replica_coordinator`'s doc).
    let index_dir = tempfile::tempdir().unwrap();
    let sync_state = Arc::new(ReplicaCoordinator::open(index_dir.path().join("index.db")).unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDevice {
        device_id: device_id.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        store_root,
        _index_dir: index_dir,
    }
}

/// Chunks `content` once (via a throwaway store, purely to compute the
/// canonical block list/hashes) and returns the block list plus each
/// block's raw bytes, so the caller can selectively populate different
/// devices' block stores with different subsets.
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

/// Installs a process-global subscriber whose filter comes from `RUST_LOG`
/// (this workspace enables tracing-subscriber's `env-filter` feature, so
/// with `RUST_LOG` unset nothing below ERROR is emitted). Not "inert": the
/// subscriber is installed either way, and the first caller in this binary
/// wins for the whole process.
///
/// Every failure in this file surfaces as a
/// bare `HydrationFailed("big.bin")`, which names the file and nothing about
/// which of the many steps between "ask a peer" and "commit the bytes"
/// refused. The daemon logs that reason, naming the predicate that declined,
/// and without a subscriber installed in this binary it goes nowhere.
fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// Indexes the file as a placeholder on `device` (no full-content write to
/// disk — this test only cares about block-store/hydration behavior) and
/// stores exactly `owned_blocks` worth of raw content in its block store.
fn seed_placeholder(
    device: &TestDevice,
    blocks: &[BlockInfo],
    total_size: u64,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    let record = seed_link_and_authority(device, blocks, total_size);
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
    finish_seed(device, owned_blocks, data_by_hash);
}

/// Seeds a peer that will ANSWER `BlockRequest`s: same as
/// [`seed_placeholder`], except the file is indexed through a real signed
/// local Change and that Change is driven to Published.
///
/// Block-serving authorization deliberately serves only blocks backed by a
/// Published Change -- `published_group_file_version_references_block`
/// joins against `change_authorization`, which a bare `upsert_file` can
/// never satisfy. A peer seeded the raw way therefore refuses every request
/// with `reason="not_referenced"` even while holding the bytes, which is
/// production behaving correctly and this fixture being older than the
/// contract. Reproduced directly, from the source side's own diagnostic:
///
/// ```text
/// reason="not_referenced"  live_record_references_hash=true
/// dag_group_file_version_references_block=Ok(false)
/// store_get_ok=true  store_get_size=131072
/// ```
///
/// The asymmetry the suite exists for is untouched: the Published version
/// legitimately references EVERY block of the file, while
/// [`finish_seed`] still stores only `owned_blocks` physically. A peer can
/// be authorized to serve a version and genuinely not hold parts of it,
/// which is exactly the case these tests construct.
///
/// Deliberately not applied to the hydrating device or to the local-only
/// scenarios: they never answer a request, so publishing there would add
/// coordination machinery for nothing.
async fn seed_published_serving_placeholder(
    device: &TestDevice,
    blocks: &[BlockInfo],
    total_size: u64,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    let record = seed_link_and_authority(device, blocks, total_size);
    let version = FileVersion::new(
        blocks
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect(),
        total_size,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
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
    finish_seed(device, owned_blocks, data_by_hash);
    // Pending is not servable. In production a checkpoint flush is triggered
    // by a new local mutation's broadcast or by a reconnect; this fixture
    // runs neither, so it asks explicitly.
    device.state.flush_pending_checkpoint_for_group_for_test(GROUP).await;
}

/// Everything both seeding helpers do before the index write: adopt the
/// root, install the test root-commit authority, and build the record.
fn seed_link_and_authority(
    device: &TestDevice,
    blocks: &[BlockInfo],
    total_size: u64,
) -> FileRecord {
    init_tracing();
    // Adopted BEFORE any index row exists for this group -- `VerifiedRoot::
    // open` refuses an ambiguous adoption once the index already has a
    // live row with nothing corresponding on disk (ordinary placeholder
    // testing here never writes real file content), which ordering this
    // after the `upsert_file` below would trigger.
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        device.root.path(),
        GROUP,
        device.state.replica_coordinator.as_ref(),
    )
    .unwrap();
    // This file never starts a real `LinkRuntimeController` watch (see its
    // own module doc -- deliberately lightweight, hand-built peer sessions
    // instead), so without this, `hydration::hydrate_inner`'s own
    // `state.root_lease_for(GROUP)` call (the very first fallible step,
    // before any peer is even contacted) fails every single hydration
    // attempt in this file with "no live root-commit authority" -- masking
    // every test that expects an error (any error satisfies `is_err()`,
    // trivially, without ever exercising the block-fetch/corruption/deadline
    // logic under test) and hard-failing every test that expects success.
    device.state.install_test_root_commit_authority(GROUP);

    FileRecord {
        path: PATH.to_string(),
        size: total_size,
        mtime_unix_nanos: 0,
        blocks: blocks.to_vec(),
        deleted: false,
    }
}

/// Everything both seeding helpers do after the index write: mark the row a
/// placeholder, make the link On-Demand, and store exactly `owned_blocks`
/// physically (with provenance), leaving every other block genuinely absent.
fn finish_seed(
    device: &TestDevice,
    owned_blocks: &[BlockInfo],
    data_by_hash: &HashMap<Vec<u8>, Vec<u8>>,
) {
    let local_path = device.root.path().to_string_lossy().to_string();
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
    for block in owned_blocks {
        device.state.block_store.put(&data_by_hash[&block.hash]).unwrap();
        // Mirrors what `LocalChangeProcessor` does for a real local edit
        // (`record_group_block_provenance`'s doc comment): without this,
        // hydration's `resolve_blocks_local_first` refuses this block as
        // never having been obtained through the group, even though the
        // bytes are physically present.
        device
            .state
            .replica_coordinator
            .record_block_provenance(GROUP, std::slice::from_ref(&block.hash))
            .unwrap();
    }
}

/// A connected pair of real, substrate-backed `SessionTransports` plus the
/// two `TestPeerNode`s they came from -- `SessionTransports` is a required
/// `PeerSyncSession` constructor parameter now (A3/A4), and a caller that
/// wants the resulting sessions to actually be reachable over these
/// transports (every test in this file does: it is exercising multi-peer
/// block hydration) must `serve_with` each node once its own session
/// exists, which can only happen after construction -- hence returning the
/// nodes too, not just the transports.
async fn transports_and_nodes(
    device_a_id: &str,
    device_b_id: &str,
) -> (
    Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    yadorilink_peer_session::ports::SessionTransports,
    yadorilink_peer_session::ports::SessionTransports,
) {
    let book = yadorilink_lane_ports::testing::TestAddressBook::new();
    let node_a =
        yadorilink_lane_ports::testing::TestPeerNode::start(device_a_id, book.clone()).await;
    let node_b = yadorilink_lane_ports::testing::TestPeerNode::start(device_b_id, book).await;
    let transports_a = node_a.transports_for(device_b_id);
    let transports_b = node_b.transports_for(device_a_id);
    (
        node_a.clone(),
        node_b.clone(),
        yadorilink_peer_session::ports::SessionTransports {
            blocks: transports_a.clone(),
            service: transports_a.clone(),
        },
        yadorilink_peer_session::ports::SessionTransports {
            blocks: transports_b.clone(),
            service: transports_b.clone(),
        },
    )
}

/// Connects `hydrating`'s session-to-`peer` (inserted into `hydrating`'s
/// own `state.peers.sessions`, as `peer_orchestrator` would) and `peer`'s
/// session-to-`hydrating` (spawned and running, so it can answer block
/// requests, but not tracked anywhere `hydrating`-side needs).
async fn connect_as_peer(hydrating: &TestDevice, peer: &TestDevice) {
    let (node_hydrating, node_peer, transports_to_peer, transports_from_hydrating) =
        transports_and_nodes(&hydrating.device_id, &peer.device_id).await;
    let hydrating_peer_store_1 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            hydrating.state.block_store.clone(),
        ),
    );
    let replica_engine_to_peer_1 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &hydrating.state.replica_coordinator,
            hydrating_peer_store_1.clone(),
        );
    let session_to_peer = PeerSyncSession::over_substrate(
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_to_peer_1,
        hydrating_peer_store_1,
        vec![GROUP.to_string()],
        transports_to_peer,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    // Every real (`DaemonState`-backed) session has a block-serve engine
    // installed by the orchestrator; without one, an incoming
    // `BlockRequest` fails closed ("no BlockServeEngine installed"), so a
    // harness session that skips it makes every peer fetch in these tests
    // fail regardless of what the peer actually holds. This hand-rolled
    // pairing predates the credit-gated serving work that added that
    // fail-closed gate — the deterministic `HydrationFailed` this line
    // fixes was exactly that gap, on both directions of the pair.
    session_to_peer.set_block_serve_engine(hydrating.state.block_serve_engine.clone());
    node_hydrating.serve_with(&peer.device_id, session_to_peer.clone());
    hydrating.state.peers.register_session(
        peer.device_id.clone(),
        session_to_peer,
        hydrating.state.local_convergence(),
    );

    let peer_peer_store_1 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            peer.state.block_store.clone(),
        ),
    );
    let replica_engine_from_hydrating_1 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &peer.state.replica_coordinator,
            peer_peer_store_1.clone(),
        );
    let session_from_hydrating = PeerSyncSession::over_substrate(
        peer.device_id.clone(),
        hydrating.device_id.clone(),
        peer.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_from_hydrating_1,
        peer_peer_store_1,
        vec![GROUP.to_string()],
        transports_from_hydrating,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    session_from_hydrating.set_block_serve_engine(peer.state.block_serve_engine.clone());
    node_peer.serve_with(&hydrating.device_id, session_from_hydrating.clone());
}

fn big_content() -> Vec<u8> {
    (0..(DEFAULT_BLOCK_SIZE * 6)).map(|i| (i % 251) as u8).collect()
}

/// blocks split across two peer sessions, each holding only
/// some of the blocks — hydration succeeds and reconstructs identical
/// content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_split_across_two_peers_each_holding_a_disjoint_subset() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 4, "test needs multiple blocks to split meaningfully");
    let half = blocks.len() / 2;

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_d = new_device("device-d");

    // One authority for the whole test: `coordination_client_config` is a
    // `OnceLock`, so assigning devices to different fakes later cannot work.
    let _authority = support::shared_checkpoint_authority(
        &[
            ("device-b", &device_b.state),
            ("device-c", &device_c.state),
            ("device-d", &device_d.state),
        ],
        &[GROUP.to_string()],
    )
    .await;

    // B and C answer block requests, so their holdings must be backed by a
    // Published Change. D only requests.
    seed_published_serving_placeholder(
        &device_b,
        &blocks,
        content.len() as u64,
        &blocks[..half],
        &data_by_hash,
    )
    .await;
    seed_published_serving_placeholder(
        &device_c,
        &blocks,
        content.len() as u64,
        &blocks[half..],
        &data_by_hash,
    )
    .await;
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(&device_d, &device_b).await;
    connect_as_peer(&device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        hydration::hydrate_reporting(&device_d.state, GROUP, PATH).await.unwrap(),
        "content that came from peers is a download"
    );

    assert_eq!(
        device_d
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Present)
    );
    let reconstructed = std::fs::read(device_d.root.path().join(PATH)).unwrap();
    assert_eq!(reconstructed, content);
    assert!(
        !hydration::hydrate_reporting(&device_d.state, GROUP, PATH).await.unwrap(),
        "asking again for a file that is now here fetches nothing"
    );
}

/// one peer reports a block not found; a second connected peer
/// does hold it — hydration still succeeds via the second peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_not_found_on_one_peer_is_fetched_from_another() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 2);

    let device_b = new_device("device-b"); // has nothing at all
    let device_c = new_device("device-c"); // has everything
    let device_d = new_device("device-d"); // hydrating

    let _authority = support::shared_checkpoint_authority(
        &[
            ("device-b", &device_b.state),
            ("device-c", &device_c.state),
            ("device-d", &device_d.state),
        ],
        &[GROUP.to_string()],
    )
    .await;

    // Both B and C answer requests -- B's whole point is answering
    // "not found" for blocks it lacks, which it can only do once it is
    // authorized to serve the version at all.
    seed_published_serving_placeholder(
        &device_b,
        &blocks,
        content.len() as u64,
        &[],
        &data_by_hash,
    )
    .await;
    seed_published_serving_placeholder(
        &device_c,
        &blocks,
        content.len() as u64,
        &blocks,
        &data_by_hash,
    )
    .await;
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(&device_d, &device_b).await;
    connect_as_peer(&device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();

    let reconstructed = std::fs::read(device_d.root.path().join(PATH)).unwrap();
    assert_eq!(reconstructed, content);
}

/// no connected peer holds one particular block — hydration
/// fails cleanly, the file remains a placeholder, and nothing corrupt is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_missing_from_every_peer_fails_hydration_cleanly() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert!(blocks.len() >= 2);
    // Neither device ever gets the *last* block.
    let owned = &blocks[..blocks.len() - 1];

    let device_b = new_device("device-b");
    let device_d = new_device("device-d");

    let _authority = support::shared_checkpoint_authority(
        &[("device-b", &device_b.state), ("device-d", &device_d.state)],
        &[GROUP.to_string()],
    )
    .await;

    // Published metadata references EVERY block including the last one;
    // the physical store deliberately holds only `owned`. That is what
    // makes the failure below a genuine physical absence rather than an
    // authorization refusal -- see the assertion at the end.
    seed_published_serving_placeholder(
        &device_b,
        &blocks,
        content.len() as u64,
        owned,
        &data_by_hash,
    )
    .await;
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(&device_d, &device_b).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = hydration::hydrate(&device_d.state, GROUP, PATH).await;
    assert!(result.is_err(), "hydration must fail when a block is unavailable from every peer");

    // ...and fail for the RIGHT reason. `is_err()` alone is not enough here:
    // before the source side was Published, this same test passed while
    // every request died at serving authorization
    // (`reason="not_referenced"`), never reaching the block store at all --
    // the same `is_err()`, a completely different proof.
    //
    // These two together pin the intended path: B is genuinely AUTHORIZED to
    // serve the missing block's version, and simply does not hold the bytes.
    let missing = &blocks[blocks.len() - 1].hash;
    assert!(
        device_b
            .state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::dag_store::published_view::published_group_file_version_references_block(
                    conn, GROUP, missing,
                )
            })
            .unwrap(),
        "the serving peer must be authorized to serve the missing block's version -- otherwise \
         this test proves an authorization refusal, not the physical-absence path it names"
    );
    assert!(
        device_b.state.block_store.get(&hex::encode(missing)).is_err(),
        "the serving peer must genuinely not hold the missing block's bytes"
    );
    assert_eq!(
        device_d
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Remote),
        "file must remain a placeholder, not end up stuck Hydrating or falsely Hydrated"
    );
    assert!(
        !device_d.root.path().join(PATH).exists(),
        "no partial/corrupt content should be written on failure"
    );
}

/// hydrating with three connected peers, all holding the full
/// file, completes correctly — not just the two-peer minimum case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hydration_succeeds_with_three_full_peers() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_e = new_device("device-e");
    let device_d = new_device("device-d");

    let _authority = support::shared_checkpoint_authority(
        &[
            ("device-b", &device_b.state),
            ("device-c", &device_c.state),
            ("device-e", &device_e.state),
            ("device-d", &device_d.state),
        ],
        &[GROUP.to_string()],
    )
    .await;

    for peer in [&device_b, &device_c, &device_e] {
        seed_published_serving_placeholder(
            peer,
            &blocks,
            content.len() as u64,
            &blocks,
            &data_by_hash,
        )
        .await;
    }
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    connect_as_peer(&device_d, &device_b).await;
    connect_as_peer(&device_d, &device_c).await;
    connect_as_peer(&device_d, &device_e).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();
    assert_eq!(std::fs::read(device_d.root.path().join(PATH)).unwrap(), content);
}

/// A non-timeout failure after entering `Hydrating` must restore the
/// retryable placeholder state.  Making the registered link root a regular
/// file forces `reconstruct_file` to fail deterministically after all blocks
/// have already been found locally, without relying on transport timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_hydration_error_restores_placeholder_state() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let peer = new_device("device-peer");
    let hydrating = new_device("device-hydrating");
    let _authority = support::shared_checkpoint_authority(
        &[("device-peer", &peer.state), ("device-hydrating", &hydrating.state)],
        &[GROUP.to_string()],
    )
    .await;

    seed_published_serving_placeholder(
        &peer,
        &blocks,
        content.len() as u64,
        &blocks,
        &data_by_hash,
    )
    .await;
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &blocks, &data_by_hash);
    connect_as_peer(&hydrating, &peer).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let root_path = hydrating.root.path().to_path_buf();
    std::fs::remove_dir_all(&root_path).unwrap();
    std::fs::write(&root_path, b"not a directory").unwrap();

    let result = hydration::hydrate(&hydrating.state, GROUP, PATH).await;
    assert!(result.is_err(), "the invalid output root must fail hydration");
    assert_eq!(
        hydrating
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Remote),
        "ordinary hydration errors must not leave the file stuck Hydrating"
    );
}

/// A corrupt hash-named block that cannot be repaired — no peer is reachable
/// to supply a good copy — is reported by `BlockStore::get` during
/// reconstruction. That ordinary error must leave the file retryable rather
/// than permanently stuck `Hydrating`. (When a peer *is* connected the
/// corrupt block is instead refetched and hydration succeeds — see
/// `corrupt_local_block_is_refetched_when_peer_exists`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_local_block_restores_placeholder_state() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    // No peer is connected, so the corrupt block genuinely cannot be
    // refetched: the checksum mismatch surfaces at reconstruction time.
    let hydrating = new_device("device-hydrating");
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &blocks, &data_by_hash);

    let hash = hex::encode(&blocks[0].hash);
    yadorilink_local_storage::segment_store::testing::corrupt_block_payload(
        hydrating.store_root.path(),
        &hash,
        b"corrupt bytes",
    )
    .unwrap();

    let result = hydration::hydrate(&hydrating.state, GROUP, PATH).await;
    assert!(result.is_err(), "an unrepairable checksum mismatch must fail hydration");
    assert_eq!(
        hydrating
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Remote),
        "corrupt-block hydration failure must restore Placeholder"
    );
}

/// the file-level deadline bounds the *whole* multi-session
/// dispatch — hydration against an unresponsive peer (connected, but
/// never answering any request) fails within roughly the configured
/// deadline rather than hanging indefinitely.
///
/// Note: this test covers the deterministic, always-guaranteed half of
/// 's goal (the deadline is a hard upper bound on the whole
/// operation). The more optimistic "a fast, fully-responsive peer's
/// share completes without waiting for a co-present unresponsive peer"
/// is *not* separately asserted here — sophisticated
/// piece-selection/peer-prioritization is explicitly out of scope
/// (round-robin/first-available assignment is deliberately simple), so
/// whether a slow peer's checked-out-but-never-returned block delays the
/// fast peer's otherwise-complete result is inherent to that simplicity,
/// not a regression to guard against here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hydration_deadline_bounds_an_unresponsive_peer() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device_b = new_device("device-b");
    let device_d = new_device("device-d");
    seed_placeholder(&device_b, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    // Connect D's session to B, but never start B's session-to-D — B is
    // reachable at the transport level but never answers anything,
    // simulating a peer that's connected yet fully unresponsive.
    // D's own real transports; B's node exists (so a lane D opens to it has
    // somewhere real to land) but B never `serve_with`s any session onto it
    // and never runs one -- the lane sits unclaimed, exactly the "connected
    // yet fully unresponsive" peer this test needs.
    let (_node_d, _node_b, transports_d, _transports_b_unused) =
        transports_and_nodes(&device_d.device_id, &device_b.device_id).await;
    let device_d_peer_store_1 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            device_d.state.block_store.clone(),
        ),
    );
    let replica_engine_d_to_b_1 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &device_d.state.replica_coordinator,
            device_d_peer_store_1.clone(),
        );
    let session_d_to_b = PeerSyncSession::over_substrate(
        device_d.device_id.clone(),
        device_b.device_id.clone(),
        device_d.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_d_to_b_1,
        device_d_peer_store_1,
        vec![GROUP.to_string()],
        transports_d,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    device_d.state.peers.register_session(
        device_b.device_id.clone(),
        session_d_to_b,
        device_d.state.local_convergence(),
    );

    let short_timeout = Duration::from_millis(500);
    let started = std::time::Instant::now();
    let result = hydration::hydrate_with_timeout(&device_d.state, GROUP, PATH, short_timeout).await;
    let elapsed = started.elapsed();

    assert!(result.is_err(), "hydration against a fully unresponsive peer must fail, not hang");
    assert!(
        elapsed < short_timeout + Duration::from_secs(2),
        "the deadline must bound the whole operation; took {elapsed:?} for a {short_timeout:?} deadline"
    );
    assert_eq!(
        device_d
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Remote)
    );
}

/// R3e: the size-aware per-block deadline (`PeerSyncSession::fetch_
/// response_timeout_for`, which replaced a single fixed 5s constant --
/// see that function's own doc comment for the measurement behind the
/// change) must still detect a genuinely silent peer -- connected, but
/// its own session task never runs, so nothing ever answers -- within a
/// bounded time close to what the formula computes for the requested
/// block's declared size. Not near-instant (which would mean the
/// deadline was somehow bypassed) and not unbounded (the property the
/// old fixed constant existed to guarantee, and which this size-aware
/// replacement must not lose).
///
/// Calls `fetch_block_sized` directly rather than going through
/// `hydration::hydrate`, to isolate this one deadline from the file-level
/// `HYDRATION_TIMEOUT`/dispatcher retry machinery entirely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_peer_is_detected_within_the_sized_per_block_deadline() {
    let device_d = new_device("device-d-silent-probe");
    let device_b = new_device("device-b-silent-probe");

    // Same fixture shape as `hydration_deadline_bounds_an_unresponsive_
    // peer` above: B is reachable at the transport level but its own
    // session task never runs, so it never answers anything.
    let (_node_d, _node_b, transports_d, _transports_b_unused) =
        transports_and_nodes(&device_d.device_id, &device_b.device_id).await;
    let device_d_peer_store_2 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            device_d.state.block_store.clone(),
        ),
    );
    let replica_engine_d_to_b_2 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &device_d.state.replica_coordinator,
            device_d_peer_store_2.clone(),
        );
    let session_d_to_b = PeerSyncSession::over_substrate(
        device_d.device_id.clone(),
        device_b.device_id.clone(),
        device_d.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_d_to_b_2,
        device_d_peer_store_2,
        vec![GROUP.to_string()],
        transports_d,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );

    // A modest, arbitrary size (well below `DEFAULT_BLOCK_SIZE`) -- large
    // enough that its top-up over the fixed baseline is meaningfully
    // nonzero, small enough that this test stays fast.
    const PROBE_BLOCK_SIZE: u64 = 16 * 1024;
    let expected = PeerSyncSession::fetch_response_timeout_for(PROBE_BLOCK_SIZE);
    let probe_hash = vec![0x11u8; 32];

    let started = std::time::Instant::now();
    let result = session_d_to_b
        .fetch_block_sized(GROUP, "silent-probe.bin", &probe_hash, PROBE_BLOCK_SIZE)
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert!(result.is_none(), "a silent peer must resolve to no data, not an error or content");
    assert!(
        elapsed + Duration::from_millis(500) >= expected,
        "resolved suspiciously fast ({elapsed:?}) for a {expected:?} sized deadline -- the \
         size-aware deadline may have been bypassed"
    );
    assert!(
        elapsed < expected + Duration::from_secs(5),
        "took {elapsed:?}, well past the sized deadline of {expected:?} -- the deadline is not \
         actually bounding this fetch"
    );
}

/// Cancelling the hydration future after it entered `Hydrating` must run
/// the same state cleanup as an ordinary error or timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_hydration_restores_placeholder_state() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let peer = new_device("device-peer");
    let hydrating = new_device("device-hydrating");
    seed_placeholder(&peer, &blocks, content.len() as u64, &blocks, &data_by_hash);
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &[], &data_by_hash);
    let (_node_hydrating, _node_peer, transports_hydrating, _transports_peer_unused) =
        transports_and_nodes(&hydrating.device_id, &peer.device_id).await;
    let hydrating_peer_store_3 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            hydrating.state.block_store.clone(),
        ),
    );
    let replica_engine_3 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &hydrating.state.replica_coordinator,
            hydrating_peer_store_3.clone(),
        );
    let session = PeerSyncSession::over_substrate(
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_3,
        hydrating_peer_store_3,
        vec![GROUP.to_string()],
        transports_hydrating,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    hydrating.state.peers.register_session(
        peer.device_id.clone(),
        session,
        hydrating.state.local_convergence(),
    );

    let state = hydrating.state.clone();
    let task = tokio::spawn(async move { hydration::hydrate(&state, GROUP, PATH).await });
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if hydrating
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state(GROUP, PATH)
                .unwrap()
                == Some(MaterializationState::Hydrating)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("hydration should enter Hydrating before cancellation");

    task.abort();
    let _ = task.await;
    assert_eq!(
        hydrating
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Remote),
        "cancelling hydration must not leave the file stuck Hydrating"
    );
}

/// Cancelling a hydration stops its fetch lanes: once the future is dropped no further block
/// arrives from the peer, so a cancelled read neither keeps downloading nor leaves the file
/// assembled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_hydration_stops_fetching_blocks_from_the_peer() {
    let content: Vec<u8> = (0..(DEFAULT_BLOCK_SIZE * 40)).map(|i| (i % 251) as u8).collect();
    let (blocks, data_by_hash) = chunk_content(&content);
    let peer = new_device("device-cancel-peer");
    let hydrating = new_device("device-cancel-hydrating");
    let _authority = support::shared_checkpoint_authority(
        &[("device-cancel-peer", &peer.state), ("device-cancel-hydrating", &hydrating.state)],
        &[GROUP.to_string()],
    )
    .await;
    seed_published_serving_placeholder(
        &peer,
        &blocks,
        content.len() as u64,
        &blocks,
        &data_by_hash,
    )
    .await;
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &[], &data_by_hash);
    // About 10 s for the whole file: far longer than the test waits.
    hydrating.state.rate_limiters.download.set_rate_bytes_per_sec(500_000);
    connect_as_peer_sharing_hydrating_rate_limiters(&hydrating, &peer).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let present = || {
        blocks
            .iter()
            .filter(|b| hydrating.state.block_store.exists(&hex::encode(&b.hash)).unwrap())
            .count()
    };
    let state = hydrating.state.clone();
    let task = tokio::spawn(async move { hydration::hydrate(&state, GROUP, PATH).await });
    tokio::time::timeout(Duration::from_secs(15), async {
        while present() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the fetch should have started");

    task.abort();
    let _ = task.await;
    // Blocks already on their way when the cancel landed may still be stored; nothing new may be
    // requested after that.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let settled = present();
    assert!(settled < blocks.len(), "the whole file was fetched before the cancel");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(present(), settled, "blocks kept arriving after the hydration was cancelled");
    assert!(
        !hydrating.root.path().join(PATH).exists(),
        "a cancelled hydration left an assembled file"
    );
}

/// A configured download rate caps *aggregate* throughput across
/// concurrent multi-peer hydration — the hydrating device's sessions to
/// two different peers share the daemon's one `state.rate_limiters`
/// instance (exactly as `peer_orchestrator`
/// wires real sessions), so fetching one block from each peer concurrently
/// draws down the *same* bucket rather than each peer's fetch getting an
/// independent full-rate allowance. Distinguishes the two by wall-clock
/// time: under a shared bucket, the combined 2-block transfer takes
/// roughly `(total_bytes - burst) / rate`; under independent per-peer
/// buckets, both blocks would complete in parallel in roughly
/// `(block_size - burst) / rate` — well under half the shared-bucket time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_rate_caps_aggregate_throughput_across_concurrent_multi_peer_hydration() {
    // Exactly 2 blocks (not `big_content`'s 6) — enough to split one per
    // peer while keeping the throttled transfer's real wall-clock time
    // reasonable for a test.
    let content: Vec<u8> = (0..(DEFAULT_BLOCK_SIZE * 2)).map(|i| (i % 251) as u8).collect();
    let (blocks, data_by_hash) = chunk_content(&content);
    assert_eq!(blocks.len(), 2, "test assumes exactly 2 blocks, one per peer");
    let half = blocks.len() / 2;

    let device_b = new_device("device-b");
    let device_c = new_device("device-c");
    let device_d = new_device("device-d");

    let _authority = support::shared_checkpoint_authority(
        &[
            ("device-b", &device_b.state),
            ("device-c", &device_c.state),
            ("device-d", &device_d.state),
        ],
        &[GROUP.to_string()],
    )
    .await;

    seed_published_serving_placeholder(
        &device_b,
        &blocks,
        content.len() as u64,
        &blocks[..half],
        &data_by_hash,
    )
    .await;
    seed_published_serving_placeholder(
        &device_c,
        &blocks,
        content.len() as u64,
        &blocks[half..],
        &data_by_hash,
    )
    .await;
    seed_placeholder(&device_d, &blocks, content.len() as u64, &[], &data_by_hash);

    // Throttle D's *shared* download bucket before connecting — every
    // session D constructs below is wired to this exact `Arc`, the same
    // way `peer_orchestrator::spawn_peer_session` wires real ones to
    // `state.rate_limiters`.
    let rate_bytes_per_sec = 50_000u64;
    device_d.state.rate_limiters.download.set_rate_bytes_per_sec(rate_bytes_per_sec);

    connect_as_peer_sharing_hydrating_rate_limiters(&device_d, &device_b).await;
    connect_as_peer_sharing_hydrating_rate_limiters(&device_d, &device_c).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let start = std::time::Instant::now();
    hydration::hydrate(&device_d.state, GROUP, PATH).await.unwrap();
    let elapsed = start.elapsed();

    let reconstructed = std::fs::read(device_d.root.path().join(PATH)).unwrap();
    assert_eq!(reconstructed, content);

    // The independent-per-peer prediction for a single ~half-content block
    // under this rate/capacity is well under 3s; a shared bucket pushes the
    // *combined* transfer well past it — see the doc comment above for the
    // exact math.
    assert!(
        elapsed >= Duration::from_secs(3),
        "expected the shared download bucket to bound aggregate throughput \
         (roughly (total_bytes - burst) / rate), took only {elapsed:?}"
    );
}

/// A placeholder whose blocks are all already present in the local block
/// store (e.g. retained from a prior version, or not yet evicted because
/// custody was never confirmed) must hydrate from local storage alone —
/// no candidate peer is connected at all here, so a hydration that
/// insisted on a reachable peer before ever checking local presence would
/// fail this file for no reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn placeholder_with_all_local_blocks_hydrates_without_peers() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device = new_device("device-solo");
    // Every block this placeholder needs is already in the local block
    // store; no peer is connected at all.
    seed_placeholder(&device, &blocks, content.len() as u64, &blocks, &data_by_hash);

    hydration::hydrate(&device.state, GROUP, PATH)
        .await
        .expect("all needed blocks are already local; hydration must not require a peer");

    assert_eq!(
        device
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Present)
    );
    assert_eq!(std::fs::read(device.root.path().join(PATH)).unwrap(), content);
}

/// One needed block is corrupt on disk locally, but a connected peer holds
/// a good copy of it — hydration must still succeed by fetching just that
/// one block from the peer, rather than failing the whole operation
/// because a shallow "is this hash's file present" check treated the
/// corrupt bytes as already-satisfied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_local_block_is_refetched_when_peer_exists() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let peer = new_device("device-peer");
    let hydrating = new_device("device-hydrating");
    let _authority = support::shared_checkpoint_authority(
        &[("device-peer", &peer.state), ("device-hydrating", &hydrating.state)],
        &[GROUP.to_string()],
    )
    .await;

    // The peer answers the refetch, so its holdings must be Published.
    seed_published_serving_placeholder(
        &peer,
        &blocks,
        content.len() as u64,
        &blocks,
        &data_by_hash,
    )
    .await;
    seed_placeholder(&hydrating, &blocks, content.len() as u64, &blocks, &data_by_hash);
    connect_as_peer(&hydrating, &peer).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let hash = hex::encode(&blocks[0].hash);
    yadorilink_local_storage::segment_store::testing::corrupt_block_payload(
        hydrating.store_root.path(),
        &hash,
        b"corrupt bytes",
    )
    .unwrap();

    hydration::hydrate(&hydrating.state, GROUP, PATH).await.expect(
        "a corrupt local block should be refetched from a peer that holds it, \
         not fail the whole hydration",
    );

    assert_eq!(std::fs::read(hydrating.root.path().join(PATH)).unwrap(), content);
}

/// A file evicted back to a placeholder while custody was never confirmed
/// (the "last known local copy" case: an on-demand device that can't yet
/// prove a full replica durably holds this version, so it fails closed and
/// keeps its cached blocks rather than reclaiming them) must remain
/// readable while completely offline — every block it needs is still in
/// the local block store even though the on-disk file itself is now a
/// placeholder marker, and no peer is reachable to re-fetch anything from.
#[cfg_attr(
    windows,
    ignore = "eviction requires a real CfAPI placeholder identity and cfapi-host dehydration; \
              this pure-Rust fixture provides neither -- same gap as \
              durability_unobtainable_content.rs's own Windows-ignored test"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_last_local_copy_remains_user_accessible_offline() {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);

    let device = new_device("device-solo");
    seed_placeholder(&device, &blocks, content.len() as u64, &blocks, &data_by_hash);
    std::fs::write(device.root.path().join(PATH), &content).unwrap();
    device
        .state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Present,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // No custody confirmer is installed on this device, so it can never
    // confirm a full replica durably holds this version — eviction fails
    // closed and retains the cached blocks (see
    // `DaemonState::full_replica_custody_confirmed`'s doc comment). This
    // test is about that custody gate, not the on-demand pipeline's own
    // real-vs-fake state, so connect the fake here (see
    // `hydration::evict`'s own per-root on-demand gate,
    // checked before the custody gate).
    device.state.set_test_on_demand_allowed(true);
    //
    // Eviction unlinks the working-tree copy only where the OS proves no writer can exist (the
    // Linux write lease); elsewhere (macOS) it keeps the file by design, so stand in for the
    // exclusion there. Armed on this thread, around the synchronous call only (the flag is
    // thread-local).
    {
        #[cfg(not(target_os = "linux"))]
        let _exclusion =
            yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
        hydration::evict(&device.state, GROUP, PATH).unwrap();
    }
    assert_eq!(
        device
            .state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        Some(MaterializationState::Remote),
        "eviction placeholders the on-disk file even when the blocks themselves are retained"
    );
    let hashes: Vec<_> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    assert!(
        device
            .state
            .block_store
            .present_blocks(&hashes)
            .unwrap()
            .into_iter()
            .all(|present| present),
        "custody-unconfirmed eviction must retain every block rather than reclaiming them"
    );

    // No peer is connected at all — offline. Every block this placeholder
    // needs is still sitting in the local block store from before eviction.
    hydration::hydrate(&device.state, GROUP, PATH)
        .await
        .expect("a retained last local copy must remain hydratable while offline");

    assert_eq!(std::fs::read(device.root.path().join(PATH)).unwrap(), content);
}

/// Like `connect_as_peer`, but wires both of the hydrating device's
/// sessions-to-peer onto `hydrating.state.rate_limiters` ("same
/// bucket" — mirrors what `peer_orchestrator::spawn_peer_session` does for
/// every real production session) instead of each session defaulting to
/// its own independent unlimited pair.
async fn connect_as_peer_sharing_hydrating_rate_limiters(
    hydrating: &TestDevice,
    peer: &TestDevice,
) {
    let (node_hydrating, node_peer, transports_to_peer, transports_from_hydrating) =
        transports_and_nodes(&hydrating.device_id, &peer.device_id).await;
    let hydrating_peer_store_2 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            hydrating.state.block_store.clone(),
        ),
    );
    let replica_engine_to_peer_2 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &hydrating.state.replica_coordinator,
            hydrating_peer_store_2.clone(),
        );
    let session_to_peer = PeerSyncSession::over_substrate(
        hydrating.device_id.clone(),
        peer.device_id.clone(),
        hydrating.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_to_peer_2,
        hydrating_peer_store_2,
        vec![GROUP.to_string()],
        transports_to_peer,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    session_to_peer.set_rate_limiters(hydrating.state.rate_limiters.clone());
    // See `connect_as_peer` on why the serve engine must be installed on
    // both directions of a hand-rolled pairing.
    session_to_peer.set_block_serve_engine(hydrating.state.block_serve_engine.clone());
    node_hydrating.serve_with(&peer.device_id, session_to_peer.clone());
    hydrating.state.peers.register_session(
        peer.device_id.clone(),
        session_to_peer,
        hydrating.state.local_convergence(),
    );

    let peer_peer_store_2 = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            peer.state.block_store.clone(),
        ),
    );
    let replica_engine_from_hydrating_2 =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &peer.state.replica_coordinator,
            peer_peer_store_2.clone(),
        );
    let session_from_hydrating = PeerSyncSession::over_substrate(
        peer.device_id.clone(),
        hydrating.device_id.clone(),
        peer.state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_from_hydrating_2,
        peer_peer_store_2,
        vec![GROUP.to_string()],
        transports_from_hydrating,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    // The serving peer's own upload bucket is irrelevant to this test (this
    // asserts on D's shared *download* bucket only) — left unlimited, the
    // session's construction default.
    session_from_hydrating.set_block_serve_engine(peer.state.block_serve_engine.clone());
    node_peer.serve_with(&hydrating.device_id, session_from_hydrating.clone());
}

// --- folder rewind: gathering historical content before anything changes ---

const REWIND_PATH: &str = "doc.txt";

/// Gives `device` a linked group where `REWIND_PATH` held `historical` at
/// T=500 and holds something else now (one Replace), and a verified
/// policy naming it and `others` as members. Nothing of `historical` is
/// stored locally.
fn seed_rewind_history(device: &TestDevice, historical: &[BlockInfo], others: &[&str]) {
    let conn = device.state.replica_coordinator.database().pool_for_test().get().unwrap();
    let insert = |seq: i64, state: &str, blocks: &[BlockInfo], at: i64| {
        let size: u64 = blocks.iter().map(|b| b.size as u64).sum();
        conn.execute(
            "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                                mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, ?6, ?7)",
            rusqlite::params![
                GROUP,
                REWIND_PATH,
                seq,
                state,
                size as i64,
                serde_json::to_string(blocks).unwrap(),
                at
            ],
        )
        .unwrap();
    };
    insert(1, "superseded", historical, 100);
    insert(2, "current", &[], 900);
    // The namespace the current row shows, settled: one live head of it.
    let current = device
        .state
        .replica_coordinator
        .file_index_repository()
        .get_version(GROUP, REWIND_PATH, 2)
        .unwrap()
        .unwrap()
        .version_hash;
    conn.execute(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, provenance) \
         VALUES (?1, ?2, 'device-peer', ?3, 1, ?4, ?5)",
        rusqlite::params![
            GROUP,
            REWIND_PATH,
            [0u8; 16].as_slice(),
            current.0.as_slice(),
            [0u8; 32].as_slice()
        ],
    )
    .unwrap();
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    let mut members = vec![(device.device_id.as_str(), WriterRole::Editor)];
    members.extend(others.iter().map(|other| (*other, WriterRole::Editor)));
    device
        .state
        .authority
        .install_test_group_policy(GROUP, GroupPolicyState::with_members_for_tests(&members));
}

async fn approved_rewind(device: &TestDevice) -> rewind::RewindExecuteRequest {
    let preview =
        rewind::preview_rewind(device.state.clone(), GROUP.into(), 500, false).await.unwrap();
    assert_eq!(preview.counts.replace, 1, "fixture: one path to restore");
    rewind::RewindExecuteRequest {
        group_id: GROUP.into(),
        target_unix_nanos: 500,
        plan_id: preview.plan_id,
    }
}

/// Two devices: A rewinds, B serves. `b_serves` picks, from the blocks of
/// A's historical content, what B publishes and what bytes it stores.
async fn rewind_pair(
    b_serves: impl FnOnce(&[BlockInfo]) -> (Vec<BlockInfo>, Vec<BlockInfo>),
) -> (TestDevice, TestDevice, Vec<BlockInfo>, support::fake_coordination::FakeCoordination) {
    let content = big_content();
    let (blocks, data_by_hash) = chunk_content(&content);
    let device_a = new_device("device-a");
    let device_b = new_device("device-b");
    let authority = support::shared_checkpoint_authority(
        &[("device-a", &device_a.state), ("device-b", &device_b.state)],
        &[GROUP.to_string()],
    )
    .await;
    let (published, owned) = b_serves(&blocks);
    if !published.is_empty() {
        let size = published.iter().map(|b| b.size as u64).sum();
        seed_published_serving_placeholder(&device_b, &published, size, &owned, &data_by_hash)
            .await;
    }
    seed_rewind_history(&device_a, &blocks, &["device-b"]);
    connect_as_peer(&device_a, &device_b).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    (device_a, device_b, blocks, authority)
}

/// The content a rewind needs is held by a connected member: it is fetched
/// through the ordinary verified block fetch and the rewind is prepared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewind_gathers_historical_content_from_a_connected_holder() {
    let (device_a, _device_b, blocks, _authority) =
        rewind_pair(|blocks| (blocks.to_vec(), blocks.to_vec())).await;
    let request = approved_rewind(&device_a).await;

    let prepared = rewind::prepare_rewind(device_a.state.clone(), request).await.unwrap();

    let run = device_a
        .state
        .replica_coordinator
        .rewind_run_repository()
        .get_run(prepared.run_id())
        .unwrap()
        .unwrap();
    assert_eq!(run.state, RewindRunState::Prefetched);
    for block in &blocks {
        assert!(
            device_a.state.block_store.get(&hex::encode(&block.hash)).is_ok(),
            "every historical block is now held locally"
        );
    }
}

/// A connected member that never had the content answers, every time it
/// is asked, that it does not hold it: with every holder connected, that
/// is content unavailable, and nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn content_every_connected_holder_declines_is_unavailable() {
    // B publishes unrelated content, so A's historical blocks are not
    // referenced on B at all.
    let other: Vec<u8> = (0..4096u32).map(|i| (i % 7) as u8).collect();
    let (other_blocks, _) = chunk_content(&other);
    let (device_a, _device_b, _blocks, _authority) =
        rewind_pair(move |_| (other_blocks.clone(), Vec::new())).await;
    let request = approved_rewind(&device_a).await;

    let error = rewind::prepare_rewind(device_a.state.clone(), request).await.err().unwrap();

    assert!(
        matches!(error, rewind::RewindPrepareError::ContentUnavailable { files: 1, .. }),
        "got {error:?}"
    );
}

/// A connected member that references the content but cannot vouch for
/// holding it refuses the request. A refusal is not "do not have": the
/// failure is transient, never content unavailable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_holder_refusing_the_request_makes_the_failure_transient() {
    let (device_a, _device_b, _blocks, _authority) =
        rewind_pair(|blocks| (blocks.to_vec(), Vec::new())).await;
    let request = approved_rewind(&device_a).await;

    let error = rewind::prepare_rewind(device_a.state.clone(), request).await.err().unwrap();

    assert!(matches!(error, rewind::RewindPrepareError::Transient { .. }), "got {error:?}");
}
