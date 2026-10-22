//! Hydration, adoption and eviction over a real peer session.
//!
//! These tests were `yadorilink-peer-session`'s until the executor they drive
//! moved into this crate. Their bodies are unchanged: what moved is ownership,
//! not behavior. The fixture they are built on lives in
//! `test_support::peer_session_fixture`, next to the `ReplicaCoordinator` it
//! is built on.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use std::sync::{Condvar, Mutex};
use std::time::Instant;
use yadorilink_daemon::test_support::peer_session_fixture::*;
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use prost::Message as _;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_ipc_proto::sync as proto;
use yadorilink_peer_session::rate_limiter::RateLimiters;
use yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES;

/// Adoption must not commit a block reference while blocks are being
/// physically deleted.
///
/// The index is what keeps a block alive. If a reference is committed while
/// the GC is midway through deleting the very block it names, the index ends
/// up pointing at bytes that are already gone — a file that looks adopted and
/// cannot be read. The gate closes that by making a reference write wait for
/// the deletion to finish.
///
/// The Change is authored locally rather than delivered by a peer: what is
/// under test is the projection path's own guard acquisition, and the old
/// version of this test only used a wire to get a Change into this device's
/// DAG. `reconcile_paths_directly` is the same entry point the daemon's
/// convergence engine calls, so nothing about the mechanism is simulated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eager_adoption_waits_for_the_block_deletion_gate_before_committing_a_reference() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    let content = b"old orphan block adopted eagerly";

    // A Change in this device's DAG whose path this device's index does not
    // name, with the block already in the store: exactly the state adoption
    // starts from, and the state a GC sweep is entitled to reclaim from. The
    // authoring commit is undone at the index only — the DAG keeps the
    // Change, so the projection below is a first adoption of it, not a
    // re-materialization of a row that already holds the reference.
    let record = device_b.producer().commit_create(GROUP, "restored.txt", content, 0);
    let orphan_hash = hex::encode(&record.blocks[0].hash);
    device_b
        .state
        .file_index_repository()
        .remove_file(GROUP, "restored.txt", &RootCommitPermit::for_tests())
        .unwrap();
    assert!(
        !device_b.state.materialization_state_repository().live_block_hashes().unwrap().contains(&orphan_hash),
        "the fixture must start with the block orphaned, or the gate assertion below proves nothing"
    );

    let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let peer_transports = device_b.node.transports_for("device-a");
    let session_b = {
        let __state = device_b.state.clone();
        let __store = device_b.store.clone();
        let __roots = device_b.sync_roots();
        let __ports = ExecutorPorts {
            root_commit_authority_provider: AlwaysValidRootCommitAuthorityProvider::shared(),
            block_write_activity_provider: Arc::new(BlockingActivityProvider {
                attempted: attempted_tx,
                release: release.clone(),
            }),
            ..ExecutorPorts::denied()
        };
        let __replica_engine =
            yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                &__state,
                __store.clone(),
            );
        runtime_from_parts(
            PeerSyncSession::over_substrate(
                device_b.device_id.clone(),
                "device-a".into(),
                __state.clone()
                    as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                __replica_engine,
                __store.clone(),
                vec![GROUP.to_string()],
                yadorilink_peer_session::ports::SessionTransports {
                    blocks: peer_transports.clone(),
                    service: peer_transports.clone(),
                },
                PeerSyncSessionDeps::denied(),
            ),
            &device_b.device_id.clone(),
            __state,
            __store,
            __roots,
            &__ports,
        )
    };

    let projecting = session_b.clone();
    let projection = tokio::spawn(async move {
        projecting
            .convergence
            .reconcile_paths_directly(
                &projecting.driver(),
                GROUP,
                std::collections::BTreeSet::from(["restored.txt".to_string()]),
            )
            .await
    });

    tokio::task::spawn_blocking(move || {
        attempted_rx.recv_timeout(Duration::from_secs(10)).expect("adoption must enter the gate")
    })
    .await
    .unwrap();
    assert!(
        !device_b
            .state
            .materialization_state_repository()
            .live_block_hashes()
            .unwrap()
            .contains(&orphan_hash),
        "eager adoption committed its block reference while physical deletion was in progress"
    );

    {
        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    projection.await.unwrap().unwrap();

    let restored_path = device_b.root_path().join("restored.txt");
    wait_until(|| restored_path.exists(), Duration::from_secs(10)).await;
    assert_eq!(std::fs::read(restored_path).unwrap(), content);
    assert!(
        device_b
            .state
            .materialization_state_repository()
            .live_block_hashes()
            .unwrap()
            .contains(&orphan_hash),
        "once the gate opens the reference must actually be committed"
    );
}

/// The same gate, for an on-demand folder.
///
/// Worth stating separately: on-demand adoption commits a reference without
/// ever fetching or writing content, so it takes a different route to the
/// same reference write — one that could plausibly be built without the guard
/// on the grounds that it writes no bytes. It still names blocks, and naming
/// them is what the gate is about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ondemand_adoption_waits_for_the_block_deletion_gate_before_committing_a_reference() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(&root_b, MaterializationPolicy::OnDemand)
        .unwrap();
    let content = b"old orphan block adopted as an on-demand placeholder";

    // See the eager test above for why the authoring commit's index row is
    // removed while the DAG keeps its Change.
    let record = device_b.producer().commit_create(GROUP, "ondemand-restored.txt", content, 0);
    let orphan_hash = hex::encode(&record.blocks[0].hash);
    device_b
        .state
        .file_index_repository()
        .remove_file(GROUP, "ondemand-restored.txt", &RootCommitPermit::for_tests())
        .unwrap();
    assert!(
        !device_b.state.materialization_state_repository().live_block_hashes().unwrap().contains(&orphan_hash),
        "the fixture must start with the block orphaned, or the gate assertion below proves nothing"
    );

    let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let peer_transports = device_b.node.transports_for("device-a");
    let session_b = {
        let __state = device_b.state.clone();
        let __store = device_b.store.clone();
        let __roots = device_b.sync_roots();
        let __ports = ExecutorPorts {
            root_commit_authority_provider: AlwaysValidRootCommitAuthorityProvider::shared(),
            block_write_activity_provider: Arc::new(BlockingActivityProvider {
                attempted: attempted_tx,
                release: release.clone(),
            }),
            ..ExecutorPorts::denied()
        };
        let __replica_engine =
            yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                &__state,
                __store.clone(),
            );
        runtime_from_parts(
            PeerSyncSession::over_substrate(
                device_b.device_id.clone(),
                "device-a".into(),
                __state.clone()
                    as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                __replica_engine,
                __store.clone(),
                vec![GROUP.to_string()],
                yadorilink_peer_session::ports::SessionTransports {
                    blocks: peer_transports.clone(),
                    service: peer_transports.clone(),
                },
                PeerSyncSessionDeps::denied(),
            ),
            &device_b.device_id.clone(),
            __state,
            __store,
            __roots,
            &__ports,
        )
    };

    let projecting = session_b.clone();
    let projection = tokio::spawn(async move {
        projecting
            .convergence
            .reconcile_paths_directly(
                &projecting.driver(),
                GROUP,
                std::collections::BTreeSet::from(["ondemand-restored.txt".to_string()]),
            )
            .await
    });

    tokio::task::spawn_blocking(move || {
        attempted_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("on-demand adoption must enter the gate")
    })
    .await
    .unwrap();
    assert!(
        !device_b
            .state
            .materialization_state_repository()
            .live_block_hashes()
            .unwrap()
            .contains(&orphan_hash),
        "on-demand adoption committed a block reference while physical deletion was in progress"
    );

    {
        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
    projection.await.unwrap().unwrap();

    wait_until(
        || {
            device_b
                .state
                .file_index_repository()
                .get_file(GROUP, "ondemand-restored.txt")
                .ok()
                .flatten()
                .is_some()
        },
        Duration::from_secs(10),
    )
    .await;
    let adopted = device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "ondemand-restored.txt")
        .unwrap()
        .unwrap();
    assert!(adopted.blocks.iter().any(|block| hex::encode(&block.hash) == orphan_hash));
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "ondemand-restored.txt")
            .unwrap(),
        Some(MaterializationState::Remote)
    );
}

/// spec "Opening a placeholder triggers
/// hydration": `PeerSyncSession::hydrate_file` must fetch a placeholder's
/// blocks on demand and materialize its real content, transitioning to
/// `Present` — the on-access path, independent of ordinary index
/// reconciliation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    windows,
    ignore = "this test drives an in-place placeholder in a linked folder through the in-process harness; on Windows an on-demand folder is a Cloud Files provider folder served by yadorilink-cfapi-host, which this harness does not run. Windows coverage: the Windows end-to-end suite scenarios 2, 3 and 7 read, hash-compare and update placeholders against the real cfapi-host"
)]
async fn hydrate_file_fetches_and_materializes_placeholder_content() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let content = vec![0x77u8; 300_000];
    let file_path = device_a.root_path().join("report.pdf");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();

    let _session_a = spawn_session(&device_a, "device-b");
    let session_b = spawn_session(&device_b, "device-a");

    let placeholder_path = device_b.root_path().join("report.pdf");
    adopt_as_placeholder(&device_b, &record);
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "report.pdf")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );

    session_b.hydrate_file(GROUP, "report.pdf").await.unwrap();

    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "report.pdf")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Present)
    );
    assert_eq!(std::fs::read(&placeholder_path).unwrap(), content);

    let record =
        device_b.state.file_index_repository().get_file(GROUP, "report.pdf").unwrap().unwrap();
    for block in &record.blocks {
        let hash_hex = hex::encode(&block.hash);
        assert!(yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &hash_hex)
            .unwrap());
    }
}

/// Convergence rehydration (`hydrate_file`, and the audit's `Equal`/`After`
/// rehydrate arms that share its body) judges what it finds at the path
/// when it starts, exactly as access hydration does: an edit written at a
/// `Remote` row's path before the attempt and not yet journalled by the
/// watcher is left for local capture rather than replaced by the remote
/// content. (An empty path is not a local change: a `Remote` row has no
/// object, and hydrating it is the normal case.)
///
/// Its baseline re-check alone cannot see the edit: it samples the edit as
/// its own baseline and finds it unchanged.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydrate_file_leaves_a_local_change_made_before_it_started() {
    for local_change in ["write", "rename_save"] {
        let device_b = Device::new("device-b").await;
        let root_b = device_b.root_path().to_string_lossy().to_string();
        link_with_completed_startup(&device_b.state, &root_b);

        // The row and its blocks; the row is `Remote`, with nothing at the
        // path, exactly as the on-demand lane leaves it.
        let content = vec![0x77u8; 300_000];
        device_b.producer().commit_create(GROUP, "report.pdf", &content, 0);
        let out_path = device_b.root_path().join("report.pdf");
        let _ = std::fs::remove_file(&out_path);
        let permit = RootCommitPermit::for_tests();
        device_b
            .state
            .materialization_state_repository()
            .set_materialization_state(GROUP, "report.pdf", MaterializationState::Remote, &permit)
            .unwrap();

        let edit = b"a local edit the watcher has not journalled yet";
        match local_change {
            "write" => std::fs::write(&out_path, edit).unwrap(),
            "rename_save" => {
                let tmp = device_b.root_path().join(".report.pdf.save");
                std::fs::write(&tmp, edit).unwrap();
                std::fs::rename(&tmp, &out_path).unwrap();
            }
            _ => unreachable!("only the two edit shapes are driven"),
        }

        let session_b = spawn_session(&device_b, "device-a");
        let result = session_b.hydrate_file(GROUP, "report.pdf").await;

        assert!(
            result.is_err(),
            "{local_change}: hydration replaced a local change made before it started: {result:?}"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            edit,
            "{local_change}: hydration overwrote an edit made before it started"
        );
        assert_ne!(
            device_b
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "report.pdf")
                .unwrap(),
            Some(MaterializationState::Present),
            "{local_change}: the row claims Hydrated over a local change"
        );
        assert!(
            device_b.state.dirty_path_repository().is_path_dirty(GROUP, "report.pdf").unwrap(),
            "{local_change}: the refused change must be journalled for local capture"
        );
    }
}

/// **Phase E finding**: `hydrate_file_with_timeout_locked`'s physical write
/// (`reconstruct_file_off_runtime`, `apply_unix_mode`, `apply_xattrs`) used
/// to run with no mutation-fence bump at all -- unlike every sibling
/// physical mutator in this codebase (`materialize`'s own hydration/
/// placeholder/content writes, the daemon's `hydration.rs::hydrate_inner`
/// for its equivalent on-demand-hydration write). An existing
/// `path_materialized_generations` proof for this path would have survived
/// this write completely untouched (the fence never moving), so a
/// concurrent, unrelated completion for the same path could have read that
/// proof as still "usable" right up to the instant `hydrate_file` silently
/// wrote real content over the placeholder. This proves the fence is now
/// genuinely bumped by the hydration write itself, not merely that
/// hydration succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydrate_file_bumps_the_mutation_fence_before_its_physical_write() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    // No peer: the fence is a property of this device's own physical write,
    // and a wire here would only be a way to put blocks in this device's
    // store and a row in its index. Authoring locally does both, then the
    // row is put back to `Remote` with nothing on disk — the state
    // hydration starts from — so `hydrate_file` finds every block already
    // present and goes straight to the write under test.
    let content = vec![0x77u8; 300_000];
    device_b.producer().commit_create(GROUP, "report.pdf", &content, 0);
    let out_path = device_b.root_path().join("report.pdf");
    let _ = std::fs::remove_file(&out_path);
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "report.pdf",
            MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let session_b = spawn_session(&device_b, "device-a");
    let fence_before = device_b.state.dag_snapshot_mutation_fence(GROUP, "report.pdf").unwrap();

    session_b.hydrate_file(GROUP, "report.pdf").await.unwrap();

    let fence_after = device_b.state.dag_snapshot_mutation_fence(GROUP, "report.pdf").unwrap();
    assert!(
        fence_after > fence_before,
        "hydrate_file's physical write must bump the mutation fence like every other physical \
         mutator (before: {fence_before}, after: {fence_after})"
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), content);
}

/// hydrating a file with no peer connected at
/// all must fail with a clear, bounded error rather than hanging forever —
/// the plain (no-network) case of "no reachable peer holds the blocks."
#[tokio::test]
async fn hydrate_file_without_any_connected_peer_fails_immediately() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    // A placeholder entry with no session/peer at all attached to it —
    // `hydrate_file` needs *some* `PeerSyncSession` to call it on, so
    // simulate "adopted as a placeholder, but the only peer that has it
    // is now disconnected" by constructing a session whose channel points
    // at a peer that immediately drops.
    // Nobody answers on device_b's block lane for "device-a", which is what
    // "the only peer that has it is gone" looks like from this side.
    let session_b = spawn_session(&device_b, "device-a");

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "unreachable.bin".into(),
                size: 100,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xCDu8; 32],
                    offset: 0,
                    size: 100,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "unreachable.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        session_b.hydrate_file_with_timeout(GROUP, "unreachable.bin", Duration::from_millis(500)),
    )
    .await
    .expect("hydrate_file must respect its own bounded timeout, not hang past it")
    .unwrap_err();
    assert!(matches!(err, yadorilink_peer_session::PeerSessionError::HydrationFailed(_)));

    // Left as a placeholder, not stuck at `Hydrating`.
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "unreachable.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );
}

/// hydrate → evict → re-hydrate must round-trip
/// to byte-identical content — eviction doesn't touch sync state (version,
/// block list), so a second hydration from the same (or any other) peer
/// reconstructs exactly the same bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    windows,
    ignore = "this test drives an in-place placeholder in a linked folder through the in-process harness; on Windows an on-demand folder is a Cloud Files provider folder served by yadorilink-cfapi-host, which this harness does not run. Windows coverage: the Windows end-to-end suite scenarios 8 and 9 evict and reopen a file against the real cfapi-host"
)]
#[cfg_attr(
    all(not(windows), not(target_os = "linux")),
    ignore = "removing an evicted file needs the Linux write lease"
)]
async fn evict_then_rehydrate_round_trips_to_identical_content() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    let content = vec![0x99u8; 250_000];
    let file_path = device_a.root_path().join("archive.zip");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();

    let _session_a = spawn_session(&device_a, "device-b");
    let session_b = spawn_session(&device_b, "device-a");

    let path_on_b = device_b.root_path().join("archive.zip");
    adopt_as_placeholder(&device_b, &record);

    session_b.hydrate_file(GROUP, "archive.zip").await.unwrap();
    assert_eq!(std::fs::read(&path_on_b).unwrap(), content);

    struct RejectCustody;
    impl yadorilink_replica_engine::custody::FullReplicaCustody for RejectCustody {
        fn confirm_exact_version(
            &self,
            _group_id: &str,
            _path: &str,
            _version_hash: &yadorilink_replica_domain::ids::VersionHash,
            _blocks: &[yadorilink_replica_domain::file::VersionBlock],
        ) -> Option<yadorilink_replica_engine::custody::CustodyStamp> {
            None
        }

        fn confirmation_still_valid(
            &self,
            _group_id: &str,
            _path: &str,
            _version_hash: &yadorilink_replica_domain::ids::VersionHash,
            _stamp: &yadorilink_replica_engine::custody::CustodyStamp,
        ) -> bool {
            false
        }
    }

    let permit = RootCommitPermit::for_tests();
    // A live session may still be reconciling the path and hold its path
    // lock for a moment after the hydration returned: eviction then reports
    // `EvictionRejected` (a designed, retryable refusal), so retry briefly.
    let mut attempts = 0;
    loop {
        let outcome = {
            yadorilink_filesystem_sync::materialization_eviction::evict_file(
                yadorilink_filesystem_sync::materialization_eviction::MaterializationContext {
                    state: device_b.state.as_ref(),
                    liveness_gate:
                        &yadorilink_filesystem_sync::block_liveness::BlockLivenessGate::default(),
                    store: device_b.store.as_ref(),
                    root: &device_b.root_path(),
                    permit: &permit,
                },
                GROUP,
                "archive.zip",
                false,
                // Custody unconfirmed here: this exercises the placeholder transition
                // and subsequent re-hydration, not block reclamation, so the cached
                // blocks are retained (fail closed) and re-hydration is a local no-op.
                &RejectCustody,
            )
        };
        match outcome {
            Err(yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError::EvictionRejected(_))
                if attempts < 100 =>
            {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            other => {
                other.unwrap();
                break;
            }
        }
    }
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "archive.zip")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );
    assert!(
        std::fs::symlink_metadata(&path_on_b).is_err(),
        "an evicted file must no longer stand in the user tree"
    );

    session_b.hydrate_file(GROUP, "archive.zip").await.unwrap();
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "archive.zip")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Present)
    );
    assert_eq!(
        std::fs::read(&path_on_b).unwrap(),
        content,
        "re-hydration must reconstruct identical content"
    );
}

/// three devices, one `OnDemand` folder group —
/// a file created on A appears as a placeholder on both B and C with no
/// content transfer; hydrating on B fetches content only there, C stays a
/// placeholder throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    windows,
    ignore = "this test drives an in-place placeholder in a linked folder through the in-process harness; on Windows an on-demand folder is a Cloud Files provider folder served by yadorilink-cfapi-host, which this harness does not run. Windows coverage: the Windows end-to-end suite runs two devices only, so the per-device property with a third device is not exercised on Windows"
)]
async fn three_devices_on_demand_hydration_is_per_device_not_group_wide() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;
    let device_c = device_a.peer("device-c").await;

    for device in [&device_b, &device_c] {
        let root = device.root_path().to_string_lossy().to_string();
        link_with_completed_startup(&device.state, &root);
        device
            .state
            .link_repository()
            .set_materialization_policy(
                &root,
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            )
            .unwrap();
    }

    let content = vec![0x99u8; 300_000];
    let file_path = device_a.root_path().join("presentation.pptx");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();

    // A is connected to both B and C directly (a star topology) — each
    // gets A's full index independently on connect.
    let _session_a_b = spawn_session(&device_a, "device-b");
    let _session_a_c = spawn_session(&device_a, "device-c");
    let session_b = spawn_session(&device_b, "device-a");
    let _session_c = spawn_session(&device_c, "device-a");

    let path_on_b = device_b.root_path().join("presentation.pptx");
    let path_on_c = device_c.root_path().join("presentation.pptx");
    // Both devices start where an on-demand adoption leaves them. That
    // adoption fetches nothing is `ondemand_adoption.rs`'s property; what is
    // under test here is that hydrating one device leaves the other alone.
    adopt_as_placeholder(&device_b, &record);
    adopt_as_placeholder(&device_c, &record);

    for device in [&device_b, &device_c] {
        assert_eq!(
            device
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "presentation.pptx")
                .unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
        );
        let record = device
            .state
            .file_index_repository()
            .get_file(GROUP, "presentation.pptx")
            .unwrap()
            .unwrap();
        for block in &record.blocks {
            let hash_hex = hex::encode(&block.hash);
            assert!(
                !yadorilink_local_storage::BlockStore::exists(device.store.as_ref(), &hash_hex)
                    .unwrap(),
                "adopting a placeholder must not fetch any block content"
            );
        }
    }

    // Opening it on B hydrates only B.
    session_b.hydrate_file(GROUP, "presentation.pptx").await.unwrap();
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "presentation.pptx")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Present)
    );
    assert_eq!(std::fs::read(&path_on_b).unwrap(), content);

    // C was never asked to hydrate and remains an untouched placeholder.
    assert_eq!(
        device_c
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "presentation.pptx")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );
    assert!(
        std::fs::read(&path_on_c).map(|bytes| bytes != content).unwrap_or(true),
        "C's path must not hold the content"
    );
    let record_c = device_c
        .state
        .file_index_repository()
        .get_file(GROUP, "presentation.pptx")
        .unwrap()
        .unwrap();
    for block in &record_c.blocks {
        let hash_hex = hex::encode(&block.hash);
        assert!(
            !yadorilink_local_storage::BlockStore::exists(device_c.store.as_ref(), &hash_hex)
                .unwrap(),
            "hydrating on B must not fetch any block content to C"
        );
    }
}

/// hydration with no reachable peer holding the
/// blocks must time out with a clear, catchable error, never hang the
/// caller indefinitely — exercised here with a short timeout to keep the
/// test itself fast (production uses `DEFAULT_HYDRATION_TIMEOUT`, task ).
/// Simulated with a real, connected channel whose peer side simply never
/// runs (so a block request is sent but never answered) — a stalled peer
/// is a more realistic "unreachable" case than a channel that fails to
/// establish at all, and exercises the same timeout path either way.
#[tokio::test]
async fn hydration_chaos_no_reachable_peer_times_out_cleanly() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // A placeholder exists locally (as if adopted from a peer earlier),
    // but the connected peer never answers the resulting block request.
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "orphaned.bin".into(),
                size: 5_000,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0x11u8; 32],
                    offset: 0,
                    size: 5_000,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "orphaned.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Nothing ever answers for "device-nobody", so the block request
    // `hydrate_file_with_timeout` makes can only end in its own timeout.
    let session_b = spawn_session(&device_b, "device-nobody");

    let started = tokio::time::Instant::now();
    let result = session_b
        .hydrate_file_with_timeout(GROUP, "orphaned.bin", Duration::from_millis(300))
        .await;
    let elapsed = started.elapsed();

    assert!(result.is_err(), "hydration with no reachable peer must return an error, not hang");
    assert!(
        elapsed < Duration::from_secs(2),
        "hydration must fail promptly on timeout, took {elapsed:?}"
    );
    // The failed attempt leaves the file as a placeholder, not stuck
    // "Hydrating" forever — a retry later is still possible.
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "orphaned.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );
}

/// a peer response is not trusted just because it arrives on the
/// encrypted channel. The bytes must hash to the requested block before
/// they are persisted or materialized -- a responder that answers the right
/// question with the wrong content is answering it wrongly, and the stream
/// having been the correct one proves nothing about what came back on it.
#[tokio::test]
async fn hydration_rejects_block_bytes_that_do_not_hash_to_the_request() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x42u8; 4096];
    let expected_hash = sha256_bytes(&expected);
    let bad_data = vec![0x24u8; 4096];
    assert_ne!(sha256_bytes(&bad_data), expected_hash);

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "tampered.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "tampered.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    // Not `spawn_session`: see the identical note in
    // `hydration_rejects_a_decompression_bomb_block_response` -- this test's
    // one hand-written fake responder answers exactly one block request,
    // which the test-only convergence driver's own concurrent repair fetch
    // for this same placeholder could otherwise race and consume.
    // `_with_root_authority`: `hydrate_file_with_timeout` below is a real
    // mutation path gated on a live root-commit authority --
    // `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()`'s deny-by-default provider would
    // otherwise make it fail fast with `NotFound` before ever sending the
    // request this test's fake responder is waiting to answer.
    let session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-a");
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        // A well-formed `Found` in every respect except the one that
        // matters: the header declares this body's real length and echoes
        // the requested hash back, so nothing about the exchange itself
        // looks wrong -- only the bytes are someone else's.
        serve_block_requests_on_lane(&responder_node_for_task, 1, |_, _| {
            BlockAnswer::found(bad_data.clone())
        })
        .await;
    });

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "tampered.bin", Duration::from_secs(3)).await;
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "invalid block bytes must fail hydration, got {result:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "mismatched bytes must not be persisted under the expected block hash"
    );
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "tampered.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );
}

/// A `Found` header declaring more bytes than any legal block must be
/// refused on the strength of the declaration alone, before a buffer that
/// size is ever allocated for it.
///
/// This is what is left of the old oversized-`total_size` defence once
/// chunking is gone. The shape of the attack is unchanged -- a peer turns a
/// number it controls into an allocation this device makes -- but there is
/// no reassembly buffer to size any more, only the single `recv_body` call
/// that reads the body off the stream. The bound therefore has to be
/// applied to the declared size before that call, which is exactly what
/// this test pins: the responder declares 16 MiB + 1 and sends no body at
/// all, and the request must still resolve promptly as unusable rather than
/// waiting for bytes that were never coming.
#[tokio::test]
async fn hydration_rejects_a_found_header_declaring_more_than_the_maximum_block_size() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x11u8; 4096];
    let expected_hash = seed_placeholder_awaiting_hydration(&device_b, "oversized.bin", &expected);

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    // Not `spawn_session`: see the identical note in
    // `hydration_rejects_a_decompression_bomb_block_response`.
    let session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-a");
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        serve_block_requests_on_lane(&responder_node_for_task, 1, |_, request| {
            BlockAnswer::FoundExactly {
                // One byte past `MAX_BLOCK_SIZE` (16 MiB): large enough to be
                // refused, and deliberately just barely so, since a bound that
                // is off by one in the permissive direction is the only kind a
                // round number would not catch.
                size: 16 * 1024 * 1024 + 1,
                hash: request.block_hash.clone(),
                compression: proto::Compression::None as i32,
                body: Vec::new(),
            }
        })
        .await;
    });

    let started = Instant::now();
    let result =
        session_b.hydrate_file_with_timeout(GROUP, "oversized.bin", Duration::from_secs(3)).await;
    let elapsed = started.elapsed();
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "a Found header above the maximum block size must fail hydration, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the oversized declaration must be refused on sight, not waited out for a body that \
         never arrives; took {elapsed:?}"
    );
    assert!(
        !yadorilink_local_storage::BlockStore::exists(
            device_b.store.as_ref(),
            &hex::encode(&expected_hash)
        )
        .unwrap(),
        "nothing may be persisted for a block whose declared size was refused"
    );
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "oversized.bin")
            .unwrap(),
        Some(MaterializationState::Remote)
    );
}

/// A `Found` header echoing a DIFFERENT hash than the request must be
/// refused, however good its bytes are.
///
/// The requester already knows which hash it asked for, so the echoed one
/// carries no information -- it is a cross-check, and this is what it
/// catches: a responder answering a question that was not asked. It is the
/// property the old `request_id` correlation defence used to provide from
/// the other direction, and it survives the move to one stream per request
/// because a stream proves only which exchange an answer belongs to, never
/// which block it is an answer about.
#[tokio::test]
async fn hydration_rejects_a_found_header_bound_to_a_different_hash() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x22u8; 4096];
    let expected_hash =
        seed_placeholder_awaiting_hydration(&device_b, "mislabelled.bin", &expected);
    let other_hash = sha256_bytes(b"some entirely different block");
    assert_ne!(other_hash, expected_hash);

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    let session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-a");
    let responder_expected = expected.clone();
    let responder_other_hash = other_hash.clone();
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        // The bytes are the genuinely correct ones -- only the identity the
        // header binds them to is wrong. Nothing but the echoed hash can
        // distinguish this from a good answer, which is the whole point of
        // checking it.
        serve_block_requests_on_lane(&responder_node_for_task, 1, |_, _| {
            BlockAnswer::FoundExactly {
                size: responder_expected.len() as u64,
                hash: responder_other_hash.clone(),
                compression: proto::Compression::None as i32,
                body: responder_expected.clone(),
            }
        })
        .await;
    });

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "mislabelled.bin", Duration::from_secs(3)).await;
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "a Found header bound to a different hash must fail hydration, got {result:?}"
    );
    for hash in [&expected_hash, &other_hash] {
        assert!(
            !yadorilink_local_storage::BlockStore::exists(
                device_b.store.as_ref(),
                &hex::encode(hash)
            )
            .unwrap(),
            "a response bound to the wrong hash must not be stored under either one"
        );
    }
}

/// `Rejected` is an answer about this peer, not about this moment: the
/// requester must stop asking it. `dont_have` is not -- it is racy enough
/// (the peer's own index may simply not have caught up yet) to be worth a
/// bounded retry, which is the behavior `Rejected` must be visibly distinct
/// from.
///
/// One test for both because the distinction, not either one alone, is the
/// property: each is counted on the responder's side, where the number of
/// requests that actually arrived is directly observable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_stops_the_requester_where_dont_have_does_not() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    seed_placeholder_awaiting_hydration(&device_b, "racy.bin", b"answered dont_have every time");
    seed_placeholder_awaiting_hydration(&device_b, "denied.bin", b"answered with a rejection");

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    let session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-a");
    // How many requests actually reached the responder, per path. Shared
    // rather than returned, because the responder task is deliberately
    // unbounded -- it cannot know in advance how many retries the requester
    // will make, which is the very thing being measured.
    let request_counts: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let responder_counts = request_counts.clone();
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        loop {
            let Some((_group, stream)) = responder_node_for_task.accept_unclaimed_lane().await
            else {
                return;
            };
            let mut stream = yadorilink_lane_ports::LaneBlockStream::new(stream);
            let header = yadorilink_peer_session::ports::PeerBlockStream::recv_message(
                &mut stream,
                MAX_BLOCK_STREAM_HEADER_BYTES,
            )
            .await
            .expect("the block stream ended before its request header");
            let request = proto::BlockRequestHeader::decode(header.as_slice())
                .expect("a block request header must decode");
            *responder_counts.lock().unwrap().entry(request.file_path.clone()).or_insert(0) += 1;
            let answer = match request.file_path.as_str() {
                "denied.bin" => BlockAnswer::Rejected {
                    reason: "requester is not authorized for this folder group".to_string(),
                },
                _ => BlockAnswer::DontHave,
            };
            answer_block_request(&mut stream, &request, answer).await;
        }
    });

    for path in ["racy.bin", "denied.bin"] {
        // The bulk fetch family (the receive engine's own lane) is what re-asks a DontHave.
        let result =
            session_b.materialize_via_convergence(GROUP, path, Duration::from_secs(10)).await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
            "no answer here supplies content, so obtaining {path} must fail; got {result:?}"
        );
    }
    responder.abort();

    let counts = request_counts.lock().unwrap();
    let dont_have = counts.get("racy.bin").copied().unwrap_or(0);
    let rejected = counts.get("denied.bin").copied().unwrap_or(0);
    assert!(
        dont_have > 1,
        "dont_have is the one answer worth re-asking about -- the peer's own index may simply \
         be behind -- so it must have been retried, but only {dont_have} request(s) arrived"
    );
    assert!(
        rejected < dont_have,
        "a rejection is a hard denial that will be answered identically every time, so it must \
         be retried strictly less than dont_have is ({rejected} vs {dont_have})"
    );
}

/// (security review): a hydration request's
/// underlying block request goes through the exact same
/// `handle_block_request` authorization check as any other block fetch —
/// there is no separate, unchecked path for on-access hydration. Verified
/// here by having the *responding* peer's session independently lack
/// authorization for the group (simulating a coordination-plane ACL that
/// doesn't actually cover this pairing), even though the requester
/// believes it does — content must never be leaked either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hydration_block_request_is_refused_for_a_group_the_peer_does_not_authorize() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    let content = vec![0xCCu8; 5_000];
    let file_path = device_a.root_path().join("secret.bin");
    std::fs::write(&file_path, &content).unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    // B already has an (independently-constructed) placeholder for this
    // group/path, as if adopted earlier while genuinely authorized.
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    let record =
        device_a.state.file_index_repository().get_file(GROUP, "secret.bin").unwrap().unwrap();
    device_b
        .state
        .file_index_repository()
        .upsert_file(GROUP, &record, &RootCommitPermit::for_tests())
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "secret.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // A's session (which will *answer* B's block requests) is constructed
    // with an empty shared-group list — A is no longer actually
    // authorized to share GROUP with B, regardless of what B believes.
    let _session_a = spawn_session_with_groups(&device_a, "device-b", vec![]);
    let session_b = spawn_session_with_groups(&device_b, "device-a", vec![GROUP.to_string()]);

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "secret.bin", Duration::from_secs(3)).await;

    assert!(result.is_err(), "hydration must fail when the peer does not authorize the group");
    assert_ne!(
        std::fs::read(device_b.root_path().join("secret.bin")).ok().as_deref(),
        Some(content.as_slice()),
        "content must never be leaked across an unauthorized group boundary"
    );
    let hash_hex = hex::encode(&record.blocks[0].hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &hash_hex).unwrap(),
        "the refused block must never land in B's block store either"
    );
}

/// A held file's record and content
/// blocks must keep flowing to peers exactly like any other record — held
/// state is a *local* materialization gate (this device won't write the
/// bytes to disk under this hazardous name), not an exclusion from index
/// exchange or block serving (the design: "the index continues tracking
/// it... so it still syncs correctly to any peer/platform where the name
/// is valid"). Held state is set up directly against device B's own
/// `ReplicaCoordinator`/`BlockStore` here rather than driven through an
/// actual case-fold collision, so this test isolates exactly the property
/// its name calls for — B, despite holding this record, still answers
/// device C's real block requests for it over an actual two-peer wire
/// connection.
///
/// The counterpart direction, a genuine tombstone clearing a real hold,
/// belongs to the hazard/tombstone tests in `exact_version_hash_tests`,
/// not here.
#[tokio::test]
async fn held_files_blocks_are_still_served_to_a_requesting_peer() {
    let device_b = Device::new("device-b").await;
    let device_c = device_b.peer("device-c").await;

    let content = b"content this device holds but never wrote to disk";
    // Committed through the DAG, not straight into the index: the heads
    // announce is what carries this record to C, and it can only announce a
    // path the change history actually contains. `commit_create` stores the
    // content block on B exactly as the direct `store.put` here used to, so
    // B still has the bytes to serve without ever writing them to disk.
    let record = device_b.producer().commit_create(GROUP, "photo.jpg", content, 0);
    device_b.publish_pending();
    device_b
        .state
        .materialization_state_repository()
        .set_held(GROUP, "photo.jpg", "case_collision: collides with existing 'Photo.jpg'", 1_000)
        .unwrap();
    assert!(
        !device_b.root_path().join("photo.jpg").exists(),
        "sanity check: nothing is on disk under the held name before B ever connects to anyone"
    );

    // No background convergence driver on either side, which is what
    // `spawn_session_without_convergence_driver` exists for: this test is
    // about the block lane, not about convergence, and it drives the one
    // request it cares about by hand.
    //
    // It matters here beyond the usual "don't race the thing under test".
    // Held is a gate on LOCAL materialization of a live record, not a
    // deletion -- so `clear_held` belongs exactly where it already is, in
    // the tombstone arm, and runs when the current desired state really has
    // become `Absent`. This fixture never gets B there: it commits a Put,
    // leaves the resulting projection obligation unsettled (B has no
    // actual-state evidence for a file it deliberately never writes), and
    // then sets held by hand. A background driver reconciling that path is
    // therefore not reproducing a genuine `HazardHeld` record at all, and
    // dissolving the hold is a property of the fixture, not of block
    // serving. Driving convergence here tested neither thing on purpose.
    // The `_with_root_authority` variant, because that is what `spawn_
    // session` itself installs: this changes the driver and nothing else,
    // and C genuinely needs a live root-commit authority to write the file
    // it hydrates.
    let _session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-c");
    let session_c =
        spawn_session_without_convergence_driver_with_root_authority(&device_c, "device-b");

    // C stands where any peer stands after adopting B's record, and asks for
    // the content. Whether B *answers* is the question; how C learned the
    // path is not.
    let path_on_c = device_c.root_path().join("photo.jpg");
    adopt_as_placeholder(&device_c, &record);
    session_c.hydrate_file(GROUP, "photo.jpg").await.unwrap();
    assert_eq!(
        std::fs::read(&path_on_c).unwrap(),
        content,
        "C must receive the real content — B served its held-but-locally-present blocks"
    );

    // B's own held state and lack of an on-disk artifact are unaffected
    // by having served the block onward to C.
    assert!(device_b
        .state
        .materialization_state_repository()
        .get_held_state(GROUP, "photo.jpg")
        .unwrap()
        .is_some());
    assert!(!device_b.root_path().join("photo.jpg").exists());
}

// --- Rate-limiting integration tests ---

/// The default (unlimited, `RateLimiters::unlimited`) session
/// configuration imposes no measurable delay on a real block transfer —
/// end-to-end confirmation alongside `rate_limiter::tests`'s unit-level one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlimited_rate_limiters_impose_no_measurable_delay_on_a_real_transfer() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    // Explicit (matches the real, un-configured default), confirming the
    // session-level plumbing itself adds no overhead either. Wired at
    // construction -- see `spawn_session_with_rate_limiters`.
    let _session_a = spawn_session_with_rate_limiters(
        &device_a,
        "device-b",
        Arc::new(RateLimiters::unlimited()),
    );
    let session_b = spawn_session_with_rate_limiters(
        &device_b,
        "device-a",
        Arc::new(RateLimiters::unlimited()),
    );

    // Session bring-up is deliberately outside the measured window, so the
    // assertion is decided by the rate limiter it names rather than by
    // connection setup. Commit the file only once the pair exists, so the measured
    // window is exactly announce -> ChangeBatch -> block fetch -> write
    // for 50 KB over an established connection: the span a rate limiter
    // is the only thing that could plausibly stretch.
    let file_path = device_a.root_path().join("unthrottled.bin");
    std::fs::write(&file_path, vec![0x22u8; 50_000]).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();

    // Same shape as the throttled case below: the measured window is the
    // block fetch alone, so what it reports is the limiter's own cost.
    adopt_as_placeholder(&device_b, &record);
    let replicated_path = device_b.root_path().join("unthrottled.bin");
    let start = std::time::Instant::now();
    session_b.hydrate_file(GROUP, "unthrottled.bin").await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(std::fs::read(&replicated_path).unwrap(), vec![0x22u8; 50_000]);
    // 10s, and the number is chosen against two floors rather than picked
    // for roundness.
    //
    // Below: landing one file costs three or four `fsync`s (the block
    // store's put, `reconstruct_file`'s own, and the parent directory's),
    // and with `TMPDIR` on a rotational disk (see `NO_PROGRESS_TIMEOUT`)
    // one `fsync` measures 100-960ms. So the
    // storage-bound floor for this transfer is seconds, not
    // milliseconds, and the old 2s bound sat underneath its own floor:
    // it was measuring the disk, and reported 2.51s / 2.66s / 2.82s
    // doing it.
    //
    // Above: the bound still has to fail if a limiter is engaged.
    // `configured_download_rate_caps_real_block_transfer_throughput`
    // below treats 4 KB/s as a meaningful configured rate; at that rate
    // this same 50 KB file takes ~11.5s. 10s therefore still separates
    // "no throttling" from the smallest throttle this file's sibling
    // test considers worth asserting on.
    assert!(
        elapsed < Duration::from_secs(10),
        "an unlimited-rate transfer should complete quickly, took {elapsed:?}"
    );
}

/// A configured non-zero download rate measurably caps real
/// block-transfer throughput — the file is small enough to be a single
/// `DEFAULT_BLOCK_SIZE` block, so the configured rate directly bounds the
/// one `fetch_block` call's `acquire` wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_download_rate_caps_real_block_transfer_throughput() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    let size = 20_000usize;
    let file_path = device_a.root_path().join("throttled.bin");
    std::fs::write(&file_path, vec![0x33u8; size]).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();

    let _session_a = spawn_session(&device_a, "device-b");
    let rate_bytes_per_sec = 4_000u64;
    // Wired at construction, not set afterwards -- see
    // `spawn_session_with_rate_limiters` for why the setter cannot be
    // used on an already-spawned session.
    let session_b = spawn_session_with_rate_limiters(
        &device_b,
        "device-a",
        Arc::new(RateLimiters::new(0, rate_bytes_per_sec)),
    );

    // The measured window is the block fetch and nothing else. Adoption is
    // set up directly rather than waited for over a wire: a delivery
    // mechanism inside the window would be measuring itself as much as the
    // limiter.
    adopt_as_placeholder(&device_b, &record);
    let replicated_path = device_b.root_path().join("throttled.bin");
    let start = std::time::Instant::now();
    session_b.hydrate_file(GROUP, "throttled.bin").await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(std::fs::read(&replicated_path).unwrap(), vec![0x33u8; size]);

    // The bucket starts with one second's worth of tokens (burst
    // allowance), so only `size - rate_bytes_per_sec` bytes are actually
    // rate-limited; generous margin for scheduling overhead.
    let expected_min_secs =
        (size as f64 - rate_bytes_per_sec as f64).max(0.0) / rate_bytes_per_sec as f64;
    let expected_min =
        Duration::from_secs_f64(expected_min_secs).saturating_sub(Duration::from_millis(750));
    assert!(
        elapsed >= expected_min,
        "expected a throttled transfer to take at least {expected_min:?}, took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------
// Transfer compression: real, wire-driven proof that compression is
// actually used end-to-end — not just that `compress_block`/
// `decompress_block` work in isolation (`peer_session::
// compression_codec_tests` already covers that). These tests either drive
// a real two-`PeerSyncSession` pair (proving content correctness through
// the real send/receive path) or pair one real session with a raw,
// manually-driven lane endpoint acting as the peer (the same pattern
// `block_request_for_unreferenced_hash_is_refused` and the hydration
// tests already use above), so the exact bytes a real session puts on the
// wire can be inspected directly.
//
// Compression is not negotiated any more: both ends of a connection are
// the same protocol generation and understand every `Compression` value,
// so a responder simply picks per payload — zstd when it helps, raw when
// compressing would inflate. What remains to prove is that the choice is
// made on the real merits of the bytes, and that either choice round-trips.
// ---------------------------------------------------------------------

/// Two real sessions must deliver byte-for-byte correct content through
/// the real compress-on-send / decompress-on-receive path — not merely
/// "sync still works," but sync still works with compression actually
/// engaged on content that compresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compressible_content_round_trips_between_two_real_sessions() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    // Highly repetitive text content (the kind of shape source trees,
    // documents, and logs typically have) spanning multiple blocks, so
    // several block fetches are exercised rather than one.
    let content = "line of repeated log-like content\n".repeat(20_000).into_bytes();
    let file_path = device_a.root_path().join("app.log");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();
    assert!(record.blocks.len() > 1, "the fixture must span several blocks");

    let _session_a = spawn_session(&device_a, "device-b");
    let session_b = spawn_session(&device_b, "device-a");

    adopt_as_placeholder(&device_b, &record);
    session_b.hydrate_file(GROUP, "app.log").await.unwrap();

    let replicated = std::fs::read(device_b.root_path().join("app.log")).unwrap();
    assert_eq!(
        replicated, content,
        "content must round-trip byte-for-byte through the real compress/decompress send path"
    );
}

/// A decompression-bomb bound: a block response declaring
/// `Compression::Zstd` whose true decompressed size vastly exceeds the
/// sync engine's `MAX_BLOCK_SIZE` (16 MiB) must be rejected without ever
/// materializing that size in memory, hydration must fail cleanly (not
/// hang or crash), and nothing must be persisted to the block store —
/// mirroring `hydration_rejects_block_bytes_that_do_not_hash_to_the_
/// request`'s structure exactly, since both are the same
/// reject-and-reassign path.
#[tokio::test]
async fn hydration_rejects_a_decompression_bomb_block_response() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x42u8; 4096];
    let expected_hash = sha256_bytes(&expected);

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "bomb.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "bomb.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // A classic zstd-bomb shape: a large, trivially-compressible buffer
    // (all zeros) compresses down to a tiny payload but claims to expand
    // to far more than `MAX_BLOCK_SIZE` (16 MiB) on decompression. Level 3
    // (not a high level) is enough — all-zero input compresses to a tiny
    // fraction of its size at any level — and keeps this light under
    // parallel test execution.
    let bomb_source = vec![0u8; 64 * 1024 * 1024];
    let bomb = zstd::stream::encode_all(bomb_source.as_slice(), 3).unwrap();
    drop(bomb_source);

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    // Not `spawn_session`: this test's subject is hydration's own bounded
    // decompression, driven by one hand-written fake responder answering
    // exactly one block request. The test-only convergence driver would
    // independently discover "bomb.bin" as a materialization repair
    // candidate and issue its own concurrent request for the same hash,
    // racing this test's explicit `hydrate_file_with_timeout` call for the
    // single canned answer below.
    // `_with_root_authority`: see the identical note in
    // `hydration_rejects_block_bytes_that_do_not_hash_to_the_request` --
    // `hydrate_file_with_timeout` below needs a live root-commit authority
    // to actually send the request this fake responder is waiting to
    // answer.
    let session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-a");
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        // The header declares only the compressed length -- which is tiny,
        // and well inside every bound the requester checks before reading.
        // The bomb is entirely in what those bytes expand to, which is what
        // makes the decompression bound (rather than the size bound) the
        // thing under test here.
        serve_block_requests_on_lane(&responder_node_for_task, 1, |_, _| BlockAnswer::Found {
            body: bomb.clone(),
            compression: proto::Compression::Zstd as i32,
        })
        .await;
    });

    let start = std::time::Instant::now();
    let result =
        session_b.hydrate_file_with_timeout(GROUP, "bomb.bin", Duration::from_secs(5)).await;
    let elapsed = start.elapsed();
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "a decompression-bomb block response must fail hydration, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "bounded decompression must reject the bomb promptly rather than spending time \
         materializing tens of megabytes it will discard; took {elapsed:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "a decompression-bomb payload must never be persisted under the expected block hash"
    );
    assert_eq!(
        device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "bomb.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    );
}

/// The other half of the same bound: a block response declaring
/// `Compression::Zstd` whose bytes aren't a valid zstd stream at all
/// (corrupted or tampered in transit) must be rejected the same way —
/// cleanly, no panic, no persisted block, hydration reported as failed.
#[tokio::test]
async fn hydration_rejects_a_corrupt_compressed_block_response() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let expected = vec![0x55u8; 4096];
    let expected_hash = sha256_bytes(&expected);

    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "corrupt.bin".into(),
                size: expected.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: expected_hash.clone(),
                    offset: 0,
                    size: expected.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "corrupt.bin",
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    // Not `spawn_session`: see the identical note in
    // `hydration_rejects_a_decompression_bomb_block_response` -- this test's
    // one hand-written fake responder answers exactly one block request,
    // which the test-only convergence driver's own concurrent repair fetch
    // for this same placeholder could otherwise race and consume.
    // `_with_root_authority`: see the identical note in
    // `hydration_rejects_block_bytes_that_do_not_hash_to_the_request` --
    // `hydrate_file_with_timeout` below needs a live root-commit authority
    // to actually send the request this fake responder is waiting to
    // answer.
    let session_b =
        spawn_session_without_convergence_driver_with_root_authority(&device_b, "device-a");
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        serve_block_requests_on_lane(&responder_node_for_task, 1, |_, _| BlockAnswer::Found {
            body: vec![0xFFu8; 256], // not a valid zstd frame
            compression: proto::Compression::Zstd as i32,
        })
        .await;
    });

    let result =
        session_b.hydrate_file_with_timeout(GROUP, "corrupt.bin", Duration::from_secs(3)).await;
    await_responder(responder).await;

    assert!(
        matches!(result, Err(yadorilink_peer_session::PeerSessionError::HydrationFailed(_))),
        "an undecompressable block response must fail hydration, got {result:?}"
    );
    let expected_hash_hex = hex::encode(&expected_hash);
    assert!(
        !yadorilink_local_storage::BlockStore::exists(device_b.store.as_ref(), &expected_hash_hex)
            .unwrap(),
        "a corrupt compressed payload must never be persisted under the expected block hash"
    );
}

/// The adaptive in-flight window: a real, end-to-end proof (not just the
/// standalone `AdaptiveWindow` unit tests) that
/// `PeerSyncSession::fetch_window` moves in response to real `fetch_block`
/// traffic over a real transport, through the actual public API
/// `yadorilink-daemon`'s multi-peer dispatcher consults
/// (`fetch_window`/`record_fetch_timeout`) — grows under many real, fast,
/// successful round trips, then shrinks once timeouts are reported the
/// way a real caller-imposed bound would report them, then grows back
/// once good conditions resume.
///
/// # Formerly failing: `AdaptiveWindow` was reading pipeline queueing as
/// # RTT inflation
///
/// `ensure_blocks_present` pipelines block fetches at a FIXED
/// `DEFAULT_BLOCK_FETCH_CONCURRENCY` (32) that has nothing to do with
/// `fetch_window`, and once more than one request to a peer is in
/// flight, that peer's OWN reply order need not match send order at
/// all -- confirmed directly, a real 8-request burst answered in
/// positions `8,6,1,7,4,5,2,3` relative to send order. A queued reply's
/// own elapsed time is therefore not attributable to any fixed share of
/// "this request's real round trip"; it is contaminated by however much
/// of its siblings' own service time happened to land ahead of it, in an
/// order not recoverable after the fact. `AdaptiveWindow::on_success`
/// read that contaminated latency as RTT inflation and applied a
/// multiplicative decrease on nearly every sample after the second, so
/// the window decayed to `ADAPTIVE_WINDOW_MIN` on the very first real
/// multi-block transfer and stayed there -- the exact inverse of what
/// the controller was introduced for (see `adaptive_window`'s own module
/// header: "Fast, low-RTT links never got to pipeline past that fixed
/// count").
///
/// Fixed at the source: `fetch_block_raw` now passes `on_success` the
/// number of requests to this peer that were outstanding when THIS one
/// was sent (`register_block_fetch_waiter`'s returned queue position). A
/// reply with a live sibling at send time can no longer trigger the
/// RTT-inflation back-off or perturb the smoothed baseline at all -- it
/// still grows the window (a successful reply under real concurrent load
/// IS positive evidence that concurrency is sustainable), but only a
/// truly isolated reply (no sibling in flight when it was sent) is
/// trusted to say anything about the link's actual RTT. See
/// `on_success`'s own doc comment for the full reasoning, and
/// `adaptive_window`'s `pipelined_replies_out_of_send_order_never_read_
/// as_inflation` unit test, which replays this exact captured burst.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    windows,
    ignore = "this test drives an in-place placeholder in a linked folder through the in-process harness; on Windows an on-demand folder is a Cloud Files provider folder served by yadorilink-cfapi-host, which this harness does not run. Windows coverage: the Windows end-to-end suite does not observe the fetch window, so this property is not exercised on Windows"
)]
async fn fetch_window_grows_under_real_traffic_and_shrinks_after_timeouts_then_recovers() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    // OnDemand on device_b so the initial index sync adopts a placeholder
    // without eagerly fetching — `hydrate_file` below then drives every
    // block fetch explicitly, giving a clean, countable burst of real
    // `fetch_block` round trips over the live direct connection.
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);
    device_b
        .state
        .link_repository()
        .set_materialization_policy(
            &root_b,
            yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
        )
        .unwrap();

    // Large enough (well past `chunker::DEFAULT_BLOCK_SIZE` = 128 KiB) to
    // split into many blocks, so `hydrate_file` issues many real
    // `fetch_block` round trips — one sample alone can't demonstrate
    // "grows under repeated good conditions."
    let content: Vec<u8> = (0..1_000_000).map(|index| (index % 251) as u8).collect();
    let file_path = device_a.root_path().join("big-archive.tar");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();

    let _session_a = spawn_session(&device_a, "device-b");
    let session_b = spawn_session(&device_b, "device-a");

    let placeholder_path = device_b.root_path().join("big-archive.tar");
    adopt_as_placeholder(&device_b, &record);

    let initial_window = session_b.session.fetch_window();

    session_b.hydrate_file(GROUP, "big-archive.tar").await.unwrap();
    assert_eq!(std::fs::read(&placeholder_path).unwrap(), content);

    let grown_window = session_b.session.fetch_window();
    assert!(
        grown_window > initial_window,
        "fetch_window should grow after many real, fast, successful block \
         fetches: {initial_window} -> {grown_window}"
    );

    // Simulate what a real caller-imposed timeout observes and reports —
    // exactly the signal `yadorilink-daemon::hydration`'s
    // `PER_BLOCK_FETCH_TIMEOUT` arm feeds via `record_fetch_timeout` when a
    // `fetch_block` future is dropped without ever answering. Real network
    // conditions bad enough to reliably reproduce this in a test are
    // impractical, so this drives the same public API a real timeout
    // caller drives.
    for _ in 0..10 {
        session_b.session.record_fetch_timeout();
    }
    let shrunk_window = session_b.session.fetch_window();
    assert!(
        shrunk_window < grown_window,
        "fetch_window should shrink after sustained timeouts: {grown_window} -> {shrunk_window}"
    );

    // Recovery: another real hydration (a second, different file) over the
    // same still-healthy connection should grow the window again from the
    // shrunk point — grow/shrink is not a one-way ratchet.
    let content2 = vec![0x5Bu8; 1_000_000];
    let file_path2 = device_a.root_path().join("second-archive.tar");
    std::fs::write(&file_path2, &content2).unwrap();
    let record2 = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path2, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    device_a.publish_pending();
    adopt_as_placeholder(&device_b, &record2);
    session_b.hydrate_file(GROUP, "second-archive.tar").await.unwrap();
    assert_eq!(std::fs::read(device_b.root_path().join("second-archive.tar")).unwrap(), content2);

    let recovered_window = session_b.session.fetch_window();
    assert!(
        recovered_window > shrunk_window,
        "fetch_window should grow back once good conditions resume: \
         {shrunk_window} -> {recovered_window}"
    );
}
