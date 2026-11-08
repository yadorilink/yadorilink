//! Test-only synchronization shared across this crate's unit tests.
//!
//! `YADORILINK_CONFIG_DIR` is a process-global env var read by
//! `device_config::config_dir` (and, transitively, by `DaemonState::new`'s
//! `GovernanceConfigStore`/`UpdateManager`/`ReportingStorage` construction).
//! Rust runs a crate's unit tests concurrently, on multiple threads of the
//! same process, by default — so any two tests that each set/restore this
//! env var independently can race and observe each other's temp directory
//! mid-test.
//!
//! `daemon_state.rs`, `device_config.rs`, and `reporting/retry.rs` each
//! used to declare their own *separate* module-local mutex for this
//! (`CONFIG_ENV_MUTEX`/`CONFIG_DIR_ENV_LOCK`/`TEST_MUTEX`), which only
//! serializes tests within the same file — not against each other. That
//! gap was real, not theoretical: adding
//! `daemon_state::tests::daemon_startup_discards_an_unverified_download_left_by_a_crash`
//! reproduced it directly — the
//! test passed reliably when run in isolation but failed once under a
//! full `cargo test --workspace` run, because a concurrently-running test
//! in one of the *other* two modules changed `YADORILINK_CONFIG_DIR`
//! between this test setting it and `DaemonState::new` reading it.
//!
//! This single shared mutex is the actual fix: every test in this crate
//! that touches `YADORILINK_CONFIG_DIR` must hold it for the env var's
//! entire set-to-restore window, regardless of which module it lives in.
//! `tokio::sync::Mutex` (rather than `std::sync::Mutex`) so it can be held
//! across `.await` points in the async tests that need that (e.g.
//! `reporting_retry::tests`'s `test_state.await`); synchronous tests
//! (`device_config.rs`) use `blocking_lock` instead.
/// The platform-wide Windows durability gate, as a test precondition: `true`
/// where the platform offers durable namespace changes (Unix always, Windows
/// once `WINDOWS_DIRECTORY_DURABILITY_VALIDATED` is set), `false` otherwise.
///
/// While the gate is closed the daemon resolves a conflict by writing the copy
/// but leaves the destructive update (replace, delete, file-to-directory)
/// waiting, so a test or test section that waits for it cannot complete. Such
/// code starts with `if !windows_durability_gate_allows_tests("what") { return; }`.
///
/// This is NOT `DurableNamespace::open(root)`, the product's capability check,
/// which also probes the volume. It deliberately does not probe: once the gate
/// opens, a CI volume that fails the probe must make these tests fail, not
/// skip them. Opening the gate re-enables every test that calls this.
pub fn windows_durability_gate_allows_tests(waits_for: &str) -> bool {
    let offered = yadorilink_fs_platform::durable_dir::platform_offers_durable_namespace();
    if !offered {
        eprintln!(
            "skipped: this platform offers no durable namespace changes, so it never completes {waits_for}"
        );
    }
    offered
}

/// A fresh state directory for one test daemon, under a directory that lives until the test
/// process exits.
///
/// `DaemonState::new` reads the process-wide `YADORILINK_CONFIG_DIR`, so every daemon an
/// integration-test process builds with it shares one state directory: its service-key pins, its
/// space-management settings, its per-device recovery areas. Tests that run as threads of one
/// process (every test of a consolidated test target, or the tests of one file) would then see
/// each other's files. A state directory of its own per daemon removes that.
#[cfg(feature = "test-support")]
pub fn isolated_state_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = ROOT.get_or_init(|| {
        // Leaked on purpose: the directories must outlive every test in the process, and the
        // operating system reclaims the temporary directory.
        tempfile::Builder::new()
            .prefix("yadorilink-test-state-")
            .tempdir()
            .expect("create the root of the test state directories")
            .keep()
    });
    let dir = root.join(format!("state-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).expect("create a test state directory");
    dir
}

/// [`isolated_daemon_state`] with sweep `intervals` for this daemon alone, over a state
/// directory `config_dir` when the test restarts a daemon (see [`isolated_daemon_state_in`]) and
/// over a fresh one otherwise.
#[cfg(feature = "test-support")]
pub fn isolated_daemon_state_with(
    intervals: crate::daemon_state::StateIntervals,
    config_dir: Option<std::path::PathBuf>,
    device_id: String,
    replica_coordinator: std::sync::Arc<crate::replica_coordinator::ReplicaCoordinator>,
    block_store: std::sync::Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync>,
) -> std::sync::Arc<crate::daemon_state::DaemonState> {
    let config_dir = config_dir.unwrap_or_else(isolated_state_dir);
    crate::daemon_state::construct_with_intervals(intervals, || {
        isolated_daemon_state_in(config_dir, device_id, replica_coordinator, block_store)
    })
}

/// [`isolated_daemon_state`] over the state directory `config_dir` rather than a fresh one: for a
/// test that restarts a daemon, which reloads the pins, settings and recovery areas the earlier
/// one left in its state directory (pass `previous.config_dir()` of the daemon being replaced).
#[cfg(feature = "test-support")]
pub fn isolated_daemon_state_in(
    config_dir: std::path::PathBuf,
    device_id: String,
    replica_coordinator: std::sync::Arc<crate::replica_coordinator::ReplicaCoordinator>,
    block_store: std::sync::Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync>,
) -> std::sync::Arc<crate::daemon_state::DaemonState> {
    let state = crate::daemon_state::DaemonState::new_in(
        config_dir,
        device_id,
        replica_coordinator,
        block_store,
    );
    release_when_the_runtime_ends(&state);
    state
}

/// Frees `state` when the Tokio runtime it was built in shuts down, which is when its test ends.
///
/// A paired state forms reference cycles with itself (its registered sessions and its peer
/// session driver reach back to it), so letting go of the last handle does not free it: its
/// databases, block store, watchers and sockets stay open until the process exits. A daemon
/// exits with its process and never notices; a test process runs hundreds of tests and
/// accumulates tens of thousands of descriptors, which is how a binary ran out of them. A task
/// parked on the runtime owns a guard that breaks the cycles when the runtime drops its tasks,
/// so no fixture has to remember to. The guard holds the state weakly: it neither keeps a state
/// alive that the test released itself nor makes a test that checks the release see a holder.
#[cfg(feature = "test-support")]
fn release_when_the_runtime_ends(state: &std::sync::Arc<crate::daemon_state::DaemonState>) {
    struct Release(std::sync::Weak<crate::daemon_state::DaemonState>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(state) = self.0.upgrade() {
                // A hook that captured the group's states reaches back to this one too.
                state.set_rebootstrap_hook_for_test(None);
                state.release_reference_cycles_for_tests();
            }
        }
    }
    // A state built outside a runtime has no test end to hook; its test frees it by hand.
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        let guard = Release(std::sync::Arc::downgrade(state));
        runtime.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
    }
}

/// [`crate::daemon_state::DaemonState::new`] over its own state directory
/// ([`isolated_state_dir`]) instead of the process-wide one.
#[cfg(feature = "test-support")]
pub fn isolated_daemon_state(
    device_id: String,
    replica_coordinator: std::sync::Arc<crate::replica_coordinator::ReplicaCoordinator>,
    block_store: std::sync::Arc<dyn yadorilink_local_storage::BlockStore + Send + Sync>,
) -> std::sync::Arc<crate::daemon_state::DaemonState> {
    isolated_daemon_state_in(isolated_state_dir(), device_id, replica_coordinator, block_store)
}

#[cfg(test)]
pub(crate) static CONFIG_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A connected pair of real, substrate-backed `SessionTransports`, for this
/// crate's own unit tests that build a `PeerSyncSession` directly (rather
/// than through `SyncStack`, which every real session goes through in
/// production).
///
/// `SessionTransports` is a required constructor parameter now (A3/A4) --
/// there is no `Option`/null/deny-by-default shape for it (see that type's
/// own doc comment for why), so every test that constructs a session needs
/// a real one. This crate is not the one that would hit the dev-dependency
/// cycle `yadorilink-peer-session`'s own unit tests have to work around
/// (`yadorilink-lane-ports` depends on this crate too, but this crate is
/// never itself a dependency of `yadorilink-lane-ports`), so it uses the
/// same real fixture (`yadorilink_lane_ports::testing::TestPeerNode`)
/// production's own `SyncStack` is built on, rather than a second,
/// in-memory-only implementation.
#[cfg(test)]
pub(crate) async fn session_transports_pair(
    device_a_id: &str,
    device_b_id: &str,
) -> (
    yadorilink_peer_session::ports::SessionTransports,
    yadorilink_peer_session::ports::SessionTransports,
) {
    use yadorilink_lane_ports::testing::{TestAddressBook, TestPeerNode};

    let book = TestAddressBook::new();
    let node_a = TestPeerNode::start(device_a_id, book.clone()).await;
    let node_b = TestPeerNode::start(device_b_id, book).await;

    let transports_a = node_a.transports_for(device_b_id);
    let transports_b = node_b.transports_for(device_a_id);
    (
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

/// Seeds the proof a prior materialization cycle left behind for `path`:
/// the fence that cycle bumped before its write, and the one commit that
/// publishes the proof, stamps `Present`, and clears the intent. Returns
/// the version it proved, which is the version the row names right now.
///
/// Fixtures need this because `Present` is a claim about two things at
/// once -- the stamp, and a usable actual-state proof naming the version
/// the row derives -- and every reader that trusts the claim checks both.
/// Seeding only the stamp produces a combination production can no longer
/// reach, so the code under test takes a path it would never take.
///
/// It goes through the internal-mutator lane, the one a device that
/// performed its own write must use, for the reason that lane's own doc
/// comment gives: the external-adoption lane mints a fresh epoch, which is
/// only correct for a change this device is discovering after the fact.
/// A fixture standing in for this device's own earlier write must not mint
/// an epoch no cycle ever minted. Publishing the proof and stamping the
/// claim through two separate calls would be the same problem from the
/// other side: one transaction produces the pair, so a row holding one
/// without the other is a state no writer can leave behind.
pub fn seed_prior_cycle_proof(
    coordinator: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
    path: &str,
    on_disk: &std::path::Path,
    permit: &yadorilink_root_authority::root_commit::RootCommitPermit,
) -> yadorilink_replica_domain::ids::VersionHash {
    use yadorilink_sync_sqlite::exact_materialized_commit::{
        ExactMaterializedState, InternalMaterializedCommit,
    };

    // The version the row itself derives -- a present object's proof has
    // to carry it, or it names no desired resolution and closes nothing.
    let version = coordinator
        .file_index_repository()
        .canonical_current_row(group_id, path)
        .expect("canonical current row")
        .expect("a seeded row to prove")
        .version_hash();
    let identity =
        yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(on_disk).unwrap();
    let mutation_generation = coordinator
        .dag_bump_mutation_fence(group_id, path, "hydration_write")
        .expect("bump the fence this seeded cycle publishes under");
    let committed = coordinator
        .materialization_state_repository()
        .commit_internal_materialized_state_if_fence_current(
            group_id,
            path,
            &ExactMaterializedState::Object {
                kind: yadorilink_replica_domain::file::RecordKind::File,
                version,
                identity: Box::new(Some(identity)),
            },
            mutation_generation,
            None,
            permit,
        )
        .expect("seed the prior cycle's commit");
    assert!(
        matches!(committed, InternalMaterializedCommit::Published(_)),
        "the seeded cycle commits under the fence it just bumped, so this must land -- a \
         silent refusal would leave the test running against an unseeded row"
    );
    version
}

/// The block-reading seam a production session gets when `state` serves blocks from the user's
/// files (`file_block_source`), for a test that builds its sessions by hand.
#[cfg(any(test, feature = "test-support"))]
pub fn file_block_source_for(
    state: &std::sync::Arc<crate::daemon_state::DaemonState>,
) -> Option<std::sync::Arc<dyn yadorilink_peer_session::ports::BlockFileSourcePort>> {
    state.tuning().file_mode.serves_from_files().then(|| {
        std::sync::Arc::new(crate::file_block_source::FileBlockSource::new(
            state.replica_coordinator.clone(),
            state.clone(),
        )) as std::sync::Arc<dyn yadorilink_peer_session::ports::BlockFileSourcePort>
    })
}

#[cfg(any(test, feature = "test-support"))]
/// Runs `hook` once, on `state`'s next handoff lease request, after the device has attested the
/// group ready and before the current versions are brought into the block store: a fixed point at
/// which a test can make a file differ from its record.
#[cfg(any(test, feature = "test-support"))]
pub fn on_next_lease_request(
    state: &std::sync::Arc<crate::daemon_state::DaemonState>,
    hook: impl FnOnce() + Send + 'static,
) {
    crate::daemon_state::arm_lease_attested_hook(&state.device_id, Box::new(hook));
}

/// A handoff lease request made as the control command makes it: the granted lease id, or the
/// stable reason code the response would carry (`None`: the daemon does not say).
#[cfg(any(test, feature = "test-support"))]
pub async fn request_lease_with_reason(
    state: &std::sync::Arc<crate::daemon_state::DaemonState>,
    group_id: &str,
) -> Result<String, Option<&'static str>> {
    use crate::application::ports::LeaseRefusal;
    match state.request_handoff_lease_checked(group_id).await {
        Ok((grant, _digest)) => Ok(grant.lease_id),
        Err(LeaseRefusal::ChangingRetry) => Err(Some("changing_retry")),
        Err(LeaseRefusal::Unspecified) => Err(None),
    }
}

/// Whether `group_id`'s captures are being asked to put their blocks into the store.
#[cfg(any(test, feature = "test-support"))]
pub fn store_mode_requested(
    state: &std::sync::Arc<crate::daemon_state::DaemonState>,
    group_id: &str,
) -> bool {
    state.replica_coordinator.store_mode_requests().requested(group_id)
}

/// Pins `path` for `group_id` through the daemon's own pin command, as the CLI's `pin` reaches it:
/// the pin is recorded, the files beneath are fetched, and the current versions are brought into the
/// block store. The answer is the reason some file beneath the pin is not yet held in the store, if
/// one is not.
#[cfg(any(test, feature = "test-support"))]
pub async fn pin_item(
    state: &std::sync::Arc<crate::daemon_state::DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<Option<&'static str>, crate::sync_error::SyncError> {
    use crate::application::ports::MaterializationPort as _;
    crate::adapters::runtime::materialization::DaemonMaterializationAdapter::new(state.clone())
        .set_rule(group_id, path, crate::application::ports::RuleChoice::Keep)
        .await
        .map(|outcome| outcome.history_not_kept_reason)
}

/// Freezes `group_id` the way a rebootstrap that reached the `Preserved` barrier does.
#[cfg(any(test, feature = "test-support"))]
pub fn freeze_group(coordinator: &crate::replica_coordinator::ReplicaCoordinator, group_id: &str) {
    coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_rebootstrap::set_journal_for_test(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
                "preserved",
                FROZEN_RECOVERY_ID,
            );
            Ok(())
        })
        .unwrap();
}

/// Records that versions `from_seq..to_seq` of `path` were dropped by the retention expiry, as the
/// expiry itself does.
#[cfg(any(test, feature = "test-support"))]
pub fn record_versions_not_kept(
    coordinator: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
    path: &str,
    from_seq: i64,
    to_seq: i64,
) {
    coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO history_freed (group_id, path, from_unix_nanos, to_unix_nanos, \
                 from_seq, to_seq, reason, recorded_unix) VALUES (?1, ?2, NULL, NULL, ?3, ?4, 'Expired', 0)",
                rusqlite::params![group_id, path, from_seq, to_seq],
            )?;
            Ok(())
        })
        .unwrap();
}

/// Ends the freeze [`freeze_group`] set, as finishing a replayed rebootstrap does.
#[cfg(any(test, feature = "test-support"))]
pub fn unfreeze_group(
    coordinator: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
) {
    coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
            yadorilink_sync_sqlite::native_rebootstrap::set_journal_for_test(
                conn,
                &group,
                "replaying",
                FROZEN_RECOVERY_ID,
            );
            assert!(yadorilink_sync_sqlite::native_rebootstrap::finish_rebootstrap(
                conn,
                &group,
                FROZEN_RECOVERY_ID
            )?);
            Ok(())
        })
        .unwrap();
}

#[cfg(any(test, feature = "test-support"))]
const FROZEN_RECOVERY_ID: &str = "recovery-under-test";

/// Local authoring for tests through the production local-capture port: a
/// save or a delete committed the way the watcher's flush commits it.
#[cfg(any(test, feature = "test-support"))]
pub mod local_seam;

/// A peer's native delta admitted through native admission, in one
/// synchronous write, as a test's setup step.
#[cfg(any(test, feature = "test-support"))]
pub mod remote_admission_fixture;

/// The two-device assembly stack-level scenarios start from: real devices,
/// a netmap pin, and honestly signed bundles. Lives here rather than beside
/// the tests that first needed it because `#[cfg(test)]` is crate-local, and
/// a scenario under `tests/` compiles against this crate as a library.
#[cfg(any(test, feature = "test-support"))]
pub mod sync_stack_fixture;

/// A second network between simulated devices, so a partition scenario can
/// tell "sync stopped" from "the devices are isolated". Shared by this
/// crate's own turmoil tests and its integration binaries, which is why it is
/// here rather than beside either.
#[cfg(any(test, feature = "test-support"))]
pub mod sim_control_plane;

/// The production provider eviction path with a scripted File Provider host, for integration
/// binaries that pair real daemons.
#[cfg(any(test, feature = "test-support"))]
pub mod provider_evict_harness;

/// The `ReplicaCoordinator`-backed peer-session integration fixture, shared
/// with `yadorilink-peer-session`'s own integration binaries while the tests
/// whose subject is materialization, hydration and convergence move to this
/// crate. See that module's own header for why it is here and what retires it.
pub mod peer_session_fixture;

/// Forces every local change still sitting in `group_id`'s debounce accumulator into the index
/// and fails unless the dirty journal is empty afterwards, so no capture of the link's own is
/// pending or opening files. Changes the operating system has not yet delivered to the
/// accumulator are not covered: write a file and wait for its capture first (see the callers).
#[cfg(any(test, feature = "test-support"))]
pub async fn drain_pending_local_changes(
    state: &crate::daemon_state::DaemonState,
    group_id: &str,
) -> Result<(), String> {
    let runtime = state
        .link_runtime_for(group_id)
        .ok_or_else(|| format!("{group_id} has no running link"))?;
    runtime.flush_pending_local_changes(group_id).await
}

/// Makes the contested versions of the daemon `device_id` count as not yet in the block store (or
/// as settled again), whatever the store holds: no fork runs on that device while it is held.
#[cfg(feature = "test-support")]
pub fn hold_contest_settling(device_id: &str, held: bool) {
    crate::contest_fork::hold_contest_settling_for_test(device_id, held);
}

/// What the provider projector does once when it starts: continues every recorded rebootstrap
/// of a provider group.
pub fn start_provider_rebootstrap_resume(state: &std::sync::Arc<crate::daemon_state::DaemonState>) {
    crate::provider_projector::resume_recorded_rebootstraps(state);
}

/// A linked folder that is watched for real, for tests that drive the daemon
/// through its control socket: an empty bootstrap policy for the group, a device
/// signing key, the link, and the link runtime (real watcher and capture). Files
/// written under `local_path` afterwards are captured as the product captures
/// them; wait for that with the index (`dag_list_versions`) before acting.
pub fn watch_link(
    state: &std::sync::Arc<crate::daemon_state::DaemonState>,
    local_path: &str,
    group_id: &str,
) {
    use crate::change_policy::{verify_group_policy_log, GroupPolicyLog};
    if state.device_signing_key().is_none() {
        state
            .set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
    }
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 0,
        current_epoch: 0,
        policy_head: vec![0; 32],
        records: Vec::new(),
    };
    let policy =
        verify_group_policy_log(&[1u8; 32], &log).expect("empty bootstrap policy verifies");
    let mut policies = std::collections::HashMap::new();
    policies.insert(group_id.to_string(), policy);
    state.authority.replace_group_policy_states(policies);
    let links = state.replica_coordinator.link_repository();
    if !links.list_links().unwrap().iter().any(|link| link.group_id == group_id) {
        links.add_link(local_path, group_id).unwrap();
    }
    crate::adapters::runtime::link_runtime_controller::LinkRuntimeController::new(state.clone())
        .start(local_path.to_string(), group_id.to_string())
        .unwrap();
}

/// Points the daemon at a stand-in coordination plane at `addr` (an offline
/// credential: requests go out without a token), as a device that is signed in.
pub fn use_coordination(state: &crate::daemon_state::DaemonState, addr: &str) {
    state.set_coordination_client_config(
        addr.to_string(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
}
