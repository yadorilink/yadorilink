#![cfg(test)]

use super::{run_ignore_recheck_pass, DaemonState};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_root_authority::root_identity::VerifiedRoot;
use yadorilink_sync_sqlite::projection_obligations::NonExactProofKind;

/// Registers a candidate session for `GROUP`, mirroring `convergence::
/// engine`'s own `build_state_with_adopted_group` -- needed only by
/// tests that go on to drive the real obligation scheduler
/// (`drive_obligations_once_for_test`) and expect it to actually
/// reconcile, not just back off for lack of any candidate.
async fn register_candidate_session(state: &Arc<DaemonState>) {
    let deps = crate::peer_orchestrator::peer_sync_session_deps(state);
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("device-local", "device-peer").await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        vec![GROUP.to_string()],
        transports,
        deps,
    );
    state.peers.register_session("device-peer".to_string(), session, state.local_convergence());
}

const GROUP: &str = "ignore-recheck-group";

fn empty_version(mtime: i64) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Same shape as `hazard_recheck_tests::build_state_with_adopted_group`.
async fn build_state_with_adopted_group() -> (Arc<DaemonState>, tempfile::TempDir) {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let replica_coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let block_store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );

    replica_coordinator.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
    VerifiedRoot::open(&root, GROUP, replica_coordinator.as_ref()).unwrap();
    let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP);
    replica_coordinator.startup_readiness().mark_group_ready(GROUP, generation);

    let state = DaemonState::build("device-local".to_string(), replica_coordinator, block_store);
    state.test_root_commit_authorities.lock().unwrap().insert(
        GROUP.to_string(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );

    (state, root_dir)
}

fn admit_change(
    state: &DaemonState,
    device: &str,
    _key: &SigningKey,
    path: &str,
    version: &FileVersion,
) -> yadorilink_replica_domain::signed_delta::NativeDelta {
    crate::test_support::remote_admission_fixture::admit_remote(
        &state.replica_coordinator,
        GROUP,
        device,
        vec![crate::test_support::remote_admission_fixture::put(
            path,
            version.version_hash,
            vec![],
        )],
        std::slice::from_ref(version),
    )
}

/// The core regression: a path parked `'ignore_blocked'` (standing in
/// for a real ignore-policy settlement -- see this module's own doc
/// comment for why a direct park, not real `.yadorilinkignore`
/// matching, is used here, mirroring `hazard_recheck_tests`' own
/// direct-`set_held` convention) with an already-admitted, trivially-
/// materializable native version is re-armed back to `'pending'` by
/// `run_ignore_recheck_pass` alone -- no new incoming record for this
/// exact path, and no `.yadorilinkignore` edit for the sweep to react
/// to -- and then converges for real once the ordinary obligation-
/// driven scheduler picks it up. RED-confirmed by commenting out the
/// re-arm loop inside `run_ignore_recheck_pass` (leaving only the
/// empty-listing early return): the parked path then never gets
/// re-examined at all, exactly the gap this closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ignore_blocked_path_is_re_examined_and_rearmed_by_the_sweep_alone() {
    let (state, root_dir) = build_state_with_adopted_group().await;
    // No `local_retirement_session` pre-warm needed here (unlike
    // `hazard_recheck_tests`' analogous setup): `run_ignore_recheck_
    // pass` is a pure ignore-policy query and
    // never constructs any `PeerSyncSession` at all, so there is no
    // first-construction-after-registration ordering hazard to avoid.
    register_candidate_session(&state).await;
    let key = SigningKey::from_bytes(&[82u8; 32]);
    admit_change(&state, "device-a", &key, "was-ignored.txt", &empty_version(1_700_000_000));

    let obligation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "was-ignored.txt")
        .unwrap()
        .expect("admission must have created an obligation");
    let claimed_g = obligation_before.invalidation_generation;
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_complete_obligation_if_non_exact_proof_current(
                GROUP,
                "was-ignored.txt",
                claimed_g,
                obligation_before.obligation_incarnation,
                NonExactProofKind::IgnoreExcluded,
            )
            .unwrap(),
        "sanity: parking the obligation as ignore_blocked must succeed"
    );
    assert_eq!(
        state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "was-ignored.txt")
            .unwrap()
            .unwrap()
            .state,
        "ignore_blocked",
        "sanity: the path must actually be parked before the sweep runs"
    );

    run_ignore_recheck_pass(&state, GROUP).await;

    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "was-ignored.txt")
        .unwrap()
        .expect("re-arming must not delete the obligation");
    assert_eq!(
        obligation.state, "pending",
        "the sweep must re-arm a path whose ignore-exclusion is already gone, with no \
         fresh incoming record for this exact path"
    );
    assert_eq!(obligation.invalidation_generation, claimed_g, "re-arming must not bump G");

    // The re-arm alone doesn't materialize anything -- it just hands
    // the path back to the ordinary scheduler. Confirm that scheduler
    // actually converges it, end to end.
    let engine = crate::convergence::engine::ConvergenceEngine::new(state.clone());
    assert!(crate::convergence::engine::drive_obligations_once_for_test(&engine, 128, 256).await);
    assert!(
        root_dir.path().join("was-ignored.txt").exists(),
        "the ordinary obligation-driven scheduler must materialize the re-armed path to disk"
    );
}

/// The specific permanent-stall hazard: gating re-arm on
/// `ProjectionAttempt::is_settled(path)` after driving a reconcile
/// attempt through `local_retirement_session` -- backed by a
/// channel that can never deliver block content -- would mean a path
/// needing an actual block fetch could never `is_settled` through that
/// session, so it could never re-arm at all -- permanently stuck `'ignore_blocked'` even
/// after the user un-ignored it. This test's own `FileVersion` carries
/// a real, non-empty block that is never written to the local block
/// store, specifically so a reconcile/materialize attempt through the
/// local-only session would hit exactly that `ChannelClosed` failure
/// -- proving re-arm depends only on the ignore-policy verdict, never
/// on whether the content happens to be fetchable through whichever
/// session ran the check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unignoring_a_path_whose_content_cannot_be_locally_fetched_still_rearms_it() {
    let (state, _root_dir) = build_state_with_adopted_group().await;
    let key = SigningKey::from_bytes(&[83u8; 32]);
    let version = FileVersion::new(
        vec![yadorilink_replica_domain::file::VersionBlock {
            hash: yadorilink_replica_domain::ids::BlockHash(vec![9u8; 32]),
            size: 4096,
        }],
        4096,
        FileMeta {
            mtime_unix_nanos: 1_700_000_200,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    admit_change(&state, "device-a", &key, "needs-a-real-fetch.bin", &version);

    let obligation_before = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "needs-a-real-fetch.bin")
        .unwrap()
        .expect("admission must have created an obligation");
    let claimed_g = obligation_before.invalidation_generation;
    assert!(
        state
            .replica_coordinator
            .sqlite()
            .dag_complete_obligation_if_non_exact_proof_current(
                GROUP,
                "needs-a-real-fetch.bin",
                claimed_g,
                obligation_before.obligation_incarnation,
                NonExactProofKind::IgnoreExcluded,
            )
            .unwrap(),
        "sanity: parking the obligation as ignore_blocked must succeed"
    );

    run_ignore_recheck_pass(&state, GROUP).await;

    let obligation = state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, "needs-a-real-fetch.bin")
        .unwrap()
        .expect("re-arming must not delete the obligation");
    assert_eq!(
        obligation.state, "pending",
        "the sweep must re-arm a path whose ignore-exclusion is gone regardless of whether \
         its content can be fetched through this sweep's own local-only session -- \
         materialization is the ordinary scheduler's job, not this sweep's"
    );
    assert_eq!(obligation.invalidation_generation, claimed_g, "re-arming must not bump G");
}

/// A group with nothing parked at all must return immediately without
/// touching anything -- the empty-listing early-return branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_with_nothing_ignore_blocked_is_a_no_op() {
    let (state, _root_dir) = build_state_with_adopted_group().await;
    run_ignore_recheck_pass(&state, GROUP).await;
    assert!(state
        .replica_coordinator
        .sqlite()
        .dag_list_ignore_blocked_paths(GROUP)
        .unwrap()
        .is_empty());
}
