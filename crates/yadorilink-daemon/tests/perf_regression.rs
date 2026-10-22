//! Before/after-style regression coverage for the two scenarios not
//! already covered by a dedicated benchmark in another crate — "large-file
//! scan" and "large-file hydration" must not block the tokio runtime (the
//! daemon's own link-runtime task wiring's `spawn_blocking`/
//! `block_in_place` wrapping, and `hydration.rs`'s `BlockStore::put`
//! `spawn_blocking` wrapping, respectively). The methodology here is
//! deliberately "after-only, but proves the actual claim" rather than a
//! literal old-code-vs-new-code A/B: the old, blocking code path no longer
//! exists to compare against directly, so instead of a wall-clock speed
//! comparison, each test proves 's real property directly — a
//! large/expensive operation running concurrently with a trivial async
//! task must not delay that trivial task, which is exactly what "don't
//! block the tokio runtime" means in practice and would reliably FAIL
//! under the pre-code (a multi-megabyte synchronous chunk/hash call
//! occupying a worker thread for its whole duration would delay a
//! concurrent timer tick by a similar order of magnitude).

use std::sync::Arc;
use std::time::{Duration, Instant};

mod support;

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{chunk_file, SegmentBlockStore};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;

const GROUP: &str = "perf-group";

async fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition never became true within timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A moderately large synthetic file (~20 MiB) — big enough that a
/// synchronous chunk/hash pass takes tens of milliseconds even on a fast
/// machine (long enough to reliably starve a concurrent timer tick if
/// nothing offloads it), without ballooning this test's own runtime or
/// disk footprint the way a genuinely multi-gigabyte file would. Only
/// used for the local-only scan test below — no network transport
/// involved, so block count doesn't matter here.
fn large_content() -> Vec<u8> {
    (0..(20 * 1024 * 1024)).map(|i| (i % 251) as u8).collect()
}

/// A smaller multi-block file (~1.5 MiB, ~12 blocks at the 128KiB
/// default block size) for the hydration test specifically — enough
/// blocks to be meaningfully "large" (several real network round trips,
/// not a single request), but deliberately far fewer than `large_content`'s
/// ~160 blocks would produce. Real, occasional transport-layer message
/// loss under load (a known, separately-diagnosed flakiness source in
/// this codebase's multi-peer hydration paths — each lost response costs
/// a `PER_BLOCK_FETCH_TIMEOUT` retry) compounds with block count: ~160
/// sequential/windowed round trips gave this test a meaningfully higher
/// chance of tripping the outer 30s `HYDRATION_TIMEOUT` under CI-level
/// contention than ~12 does, and this test's actual point (proving
/// `spawn_blocking` keeps the runtime responsive during hydration) needs
/// "more than one block," not "as many blocks as possible."
fn hydration_content() -> Vec<u8> {
    (0..(12 * 128 * 1024)).map(|i| (i % 251) as u8).collect()
}

/// (the daemon's own link-runtime task wiring's wrapping of the initial `scan_existing_files`
/// call in `spawn_blocking`): scanning a large pre-existing file must not
/// delay an unrelated, concurrently-scheduled async task on the same
/// runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_file_scan_does_not_block_concurrent_async_work() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    // A registered (non-empty device_id) DaemonState with no signing key
    // fails closed in `build_change_processor` -- see that
    // function's own doc comment: without one, this device's local edits
    // would be indexed but never recorded as DAG changes, which is silent
    // data loss from the group's perspective, not a legitimate no-emitter
    // path.
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]));
    // `add_link` below makes the group "introduced", and a group with no
    // verified policy snapshot now fails closed: `resolve_group_policy`
    // returns Withhold, every emitting write returns `PolicyUnavailable`,
    // and the scan treats that as "withhold this chunk, journal dirty,
    // break" -- so `large.bin` never reaches the index and the wait at the
    // end of this test expires. The reactor property this test is actually
    // about passes either way; this restores the precondition it needs to
    // get far enough to state it. Byte-identical to what
    // `link_runtime_controller` installs for the same purpose.
    sync_state.set_local_policy_head_provider(std::sync::Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();

    std::fs::write(root.path().join("large.bin"), large_content()).unwrap();
    sync_state.link_repository().add_link(&root.path().to_string_lossy(), GROUP).unwrap();

    // A trivial, otherwise-unrelated timer task competing for the same
    // worker pool. If the large scan blocks a worker thread, this tick
    // (scheduled to fire almost immediately) gets delayed behind it.
    let tick_started = Instant::now();
    let tick_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        tick_started.elapsed()
    });

    let controller = LinkRuntimeController::new(state.clone());
    controller.start(root.path().to_string_lossy().into(), GROUP.into()).unwrap();

    let tick_delay = tokio::time::timeout(Duration::from_secs(10), tick_task)
        .await
        .expect("timer tick never completed — large scan appears to be blocking the runtime")
        .unwrap();

    // Generous bound (the tick itself only sleeps 5ms) — this isn't
    // measuring precise scheduling latency, just ruling out "blocked for
    // the whole multi-ten-millisecond scan duration."
    assert!(
        tick_delay < Duration::from_millis(500),
        "timer tick took {tick_delay:?} to complete — large file scan appears to be blocking a tokio worker thread"
    );

    wait_until(
        || sync_state.file_index_repository().get_file(GROUP, "large.bin").ok().flatten().is_some(),
        Duration::from_secs(10),
    )
    .await;
    controller.stop(&root.path().to_string_lossy()).await;
}

/// (`hydration.rs`'s `spawn_blocking` wrap around `BlockStore::put`
/// in `fetch_blocks_from_sessions`'s worker loop): hydrating a large file
/// must not delay an unrelated, concurrently-scheduled async task either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end measurement read top to bottom; splitting it would only \
              move the setup away from the timing it bounds"
)]
async fn large_file_hydration_does_not_block_concurrent_async_work() {
    let content = hydration_content();
    let source_dir = tempfile::tempdir().unwrap();
    let source_store = Arc::new(SegmentBlockStore::new(source_dir.path()).unwrap());
    let blocks = {
        let tmp_file = source_dir.path().join("source.bin");
        std::fs::write(&tmp_file, &content).unwrap();
        chunk_file(source_store.as_ref(), &tmp_file).unwrap()
    };
    assert!(blocks.len() > 4, "test needs a real multi-block file to be meaningful");

    let dest_dir = tempfile::tempdir().unwrap();
    let dest_store = Arc::new(SegmentBlockStore::new(dest_dir.path()).unwrap());
    let dest_sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let dest_root = tempfile::tempdir().unwrap();
    dest_sync_state.link_repository().add_link(&dest_root.path().to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        dest_root.path(),
        GROUP,
        dest_sync_state.as_ref(),
    )
    .unwrap();
    dest_sync_state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "large.bin".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: blocks.clone(),
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    dest_sync_state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "large.bin",
            MaterializationState::Remote,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let dest_state = DaemonState::new("device-dest".into(), dest_sync_state.clone(), dest_store);
    // `hydrate` fails closed via `root_lease_for` unless the daemon is
    // actively linked/watching the group -- this test builds `dest_state`
    // directly rather than through full daemon startup, so it never pays
    // for a real `start_link_watch`. Same reasoning as every other
    // hydration test's `install_test_root_commit_authority` call.
    dest_state.install_test_root_commit_authority(GROUP);

    // `SessionTransports` is a required `PeerSyncSession` constructor
    // parameter now (A3/A4): a real substrate-backed pair, same fixture
    // `yadorilink-lane-ports`' own tests and `yadorilink-peer-session`'s
    // external integration crate use.
    let book = yadorilink_lane_ports::testing::TestAddressBook::new();
    let node_source =
        yadorilink_lane_ports::testing::TestPeerNode::start("device-source", book.clone()).await;
    let node_dest = yadorilink_lane_ports::testing::TestPeerNode::start("device-dest", book).await;
    let transports_source = node_source.transports_for("device-dest");
    let transports_dest = node_dest.transports_for("device-source");
    let session_transports_source = yadorilink_peer_session::ports::SessionTransports {
        blocks: transports_source.clone(),
        service: transports_source.clone(),
    };
    let session_transports_dest = yadorilink_peer_session::ports::SessionTransports {
        blocks: transports_dest.clone(),
        service: transports_dest.clone(),
    };

    // The serving side needs its own link for the group, exactly as the
    // receiving side has: sync roots are derived from the link table in
    // production (`sync_roots_for_groups` reads `list_links`), so a session
    // holding a root the link table does not know about is a state the daemon
    // cannot produce -- and the peer-apply path refuses it, which here would
    // stop this side ever learning (and so serving) the blocks under test.
    let source_sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    source_sync_state
        .link_repository()
        .add_link(&source_dir.path().to_string_lossy(), GROUP)
        .unwrap();
    let source_record =
        dest_sync_state.file_index_repository().get_file(GROUP, "large.bin").unwrap().unwrap();
    // The source must PUBLISH this version, not merely index it. Block
    // serving authorization joins `change_authorization`, so a bare
    // `upsert_file` row can never satisfy it and every block request comes
    // back refused -- which reaches this test as `HydrationFailed`, long
    // before it can observe the concurrent-async-work property it is about.
    let source_state =
        DaemonState::new("device-source".into(), source_sync_state.clone(), source_store.clone());
    source_state.install_test_root_commit_authority(GROUP);
    let source_version = yadorilink_replica_domain::file::FileVersion::new(
        source_record
            .blocks
            .iter()
            .map(|block| yadorilink_replica_domain::file::VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(block.hash.clone()),
                size: block.size,
            })
            .collect(),
        source_record.size,
        yadorilink_replica_domain::file::FileMeta {
            mtime_unix_nanos: source_record.mtime_unix_nanos,
            unix_mode: None,
            symlink_target: None,
            record_kind: yadorilink_replica_domain::file::RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let source_signing = yadorilink_transport::DeviceSigningKeyPair::generate().signing;
    source_state.set_device_signing_key(source_signing.clone());
    let source_emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
        &source_state.replica_coordinator,
        "device-source",
        source_signing,
    )
    .unwrap();
    // One checkpoint issuer for both devices: `coordination_client_config`
    // is a `OnceLock`, so the authority has to be chosen before either side
    // needs one.
    let _authority = support::shared_checkpoint_authority(
        &[("device-source", &source_state), ("device-dest", &dest_state)],
        &[GROUP.to_string()],
    )
    .await;
    yadorilink_daemon::test_support::local_seam::commit_local_upsert(
        &source_state.replica_coordinator,
        GROUP,
        &source_record,
        "device-source",
        &source_version,
        None,
        &source_emitter,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    // `chunk_file` above only writes these blocks into the source's own CAS
    // store -- it does not record group provenance for them, which the real
    // local-write path (`local_change.rs`) always does alongside a chunk
    // write. `handle_block_request`'s serving-authorization gate refuses any
    // block without it (`group_has_block_provenance`), so without this the
    // source would refuse every block request from the dest side as
    // not_found, and hydration would exhaust its retries and time out
    // instead of exercising the concurrent-async-work property under test.
    let block_hashes: Vec<Vec<u8>> = blocks.iter().map(|block| block.hash.clone()).collect();
    source_sync_state.record_block_provenance(GROUP, &block_hashes).unwrap();
    // Pending is not servable. This fixture triggers neither of production's
    // flush triggers (a new local mutation's broadcast, or a reconnect), so
    // it has to ask.
    source_state.flush_pending_checkpoint_for_group_for_test(GROUP).await;
    let generation = source_sync_state.startup_readiness().begin_group_startup(GROUP);
    source_sync_state.startup_readiness().mark_group_ready(GROUP, generation);
    let replica_engine_source =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &source_sync_state,
            source_store.clone(),
        );
    let session_source = PeerSyncSession::over_substrate(
        "device-source".into(),
        "device-dest".into(),
        source_sync_state as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_source,
        source_store,
        vec![GROUP.to_string()],
        session_transports_source,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    node_source.serve_with("device-dest", session_source.clone());
    // Production sessions always receive the daemon-wide mandatory stage-2
    // serving engine in `peer_orchestrator`. This test constructs sessions
    // directly, so install the equivalent engine explicitly; without it the
    // source correctly fails closed with `BlockReply::Rejected`.
    session_source.set_block_serve_engine(
        yadorilink_peer_session::block_serve::BlockServeEngine::new(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            1_000,
        ),
    );

    let dest_peer_store = std::sync::Arc::new(
        yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            dest_state.block_store.clone(),
        ),
    );
    let replica_engine_dest =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &dest_sync_state,
            dest_peer_store.clone(),
        );
    let session_dest = PeerSyncSession::over_substrate(
        "device-dest".into(),
        "device-source".into(),
        dest_sync_state.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine_dest,
        dest_peer_store,
        vec![GROUP.to_string()],
        session_transports_dest,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
    );
    node_dest.serve_with("device-source", session_dest.clone());
    session_dest.set_block_serve_engine(dest_state.block_serve_engine.clone());
    dest_state.peers.register_session(
        "device-source".into(),
        session_dest,
        dest_state.local_convergence(),
    );

    tokio::time::sleep(Duration::from_millis(200)).await;

    let tick_started = Instant::now();
    let tick_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        tick_started.elapsed()
    });

    let dest_state_arc = Arc::new(dest_state);
    // The 200ms sleep above is a head start, not a guarantee: the lanes
    // between the two nodes still have to come up before either side is a
    // usable hydration candidate, and that can occasionally take longer
    // than 200ms on a loaded runner (hydrate then correctly reports "no
    // candidate yet", not a hang). Retrying tolerates that startup race
    // without weakening what this test actually verifies (that a real, in-progress hydration doesn't
    // block the runtime) -- once a hydration attempt gets far enough to
    // actually start fetching blocks, this loop's job is done.
    let mut hydrate_attempts = 0;
    loop {
        match hydration::hydrate(&dest_state_arc, GROUP, "large.bin").await {
            Ok(()) => break,
            Err(e) if hydrate_attempts < 10 => {
                hydrate_attempts += 1;
                eprintln!("hydrate attempt {hydrate_attempts} failed ({e:?}), retrying...");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("hydrate never succeeded after {hydrate_attempts} retries: {e:?}"),
        }
    }

    let tick_delay = tokio::time::timeout(Duration::from_secs(10), tick_task)
        .await
        .expect(
            "timer tick never completed — large file hydration appears to be blocking the runtime",
        )
        .unwrap();
    assert!(
        tick_delay < Duration::from_millis(500),
        "timer tick took {tick_delay:?} to complete — large file hydration appears to be blocking a tokio worker thread"
    );

    assert_eq!(std::fs::read(dest_root.path().join("large.bin")).unwrap(), content);
}
