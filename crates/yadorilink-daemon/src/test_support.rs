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
