//! Proves the whole sharing-roles authorization pipeline works together,
//! not just each half in isolation.
//!
//! Under checkpoint admission, there is exactly ONE writer-authorization enforcement point
//! left: checkpoint ISSUANCE, server-side on the coordination plane. Local
//! emission is unconditional (any device may author a Pending Change
//! regardless of role -- see `replica_coordinator.rs`'s
//! `LocalPolicyHeadProvider` doc comment), and a Change with no checkpoint
//! is structurally ineligible for `send_change_batch` to ever serve, so
//! there is no "local gate a malicious client could bypass" left to prove
//! defense-in-depth against -- the old scenarios (c)/(g)/(h) (a bypassed
//! local gate, and a stale pre-downgrade `ChangeAuth` pin replay) tested
//! exactly that removed mechanism and were deleted rather than patched:
//! their premise cannot be constructed under the new architecture without
//! forging a wire-level checkpoint directly, which belongs to
//! `yadorilink-peer-session`'s own wire-protocol test suite (see its
//! "tampered checkpoint/proof/key/Change/reference fails" requirement
//! there), not this crate's real-daemon end-to-end harness.
//!
//! This file drives the real pipeline: a real signed role-carrying grant
//! record (`support::fake_coordination::FakeCoordination::grant_role`,
//! built with this crate's own `change_policy::policy_signing::
//! grant_record` -- the exact shape the coordination service's
//! `recordGrantWithRole` produces) is served over a real HTTP/WebSocket
//! netmap subscription, fetched and verified by a real daemon
//! (`peer_orchestrator::run`), and enforced by the fake coordination
//! plane's own checkpoint-issuance endpoint refusing a non-writer's
//! request -- full-stack, like `revocation_end_to_end.rs`'s own tests.
//!
//! Two scenarios:
//!   (a) a Viewer-granted device's own local edit is captured locally as a
//!       Pending Change but never syncs anywhere -- checkpoint issuance
//!       refuses it.
//!   (b) the same setup with an Editor grant instead: the local edit gets
//!       checkpointed and syncs normally -- the control proving this
//!       harness genuinely distinguishes the two roles.
//!
//! A second pair covers a DIFFERENT code path guarded by the same
//! checkpoint-issuance gate: `dag_import::ensure_initial_import`/
//! `backfill_missing_history`, which convert a device's pre-existing
//! on-disk content into signed change history the first time a group is
//! linked (or via the mid-life coverage audit) -- not the live
//! filesystem-watcher path scenarios (a)/(b) drive.
//!   (d) a Viewer-granted device's pre-existing content (written to disk
//!       before the group is linked) is never checkpointed and never syncs
//!       to a peer.
//!   (e) the same setup with an Editor grant instead: the pre-existing
//!       content imports and syncs normally.
//!
//! A third pair covers a LIVE role CHANGE while a session is already
//! connected -- the security property that a privilege reduction must
//! invalidate an already-established session's authority promptly, not
//! merely on its next reconnect. `support::fake_coordination::
//! FakeCoordination::downgrade_role` drives the exact chained
//! Revoke-then-Grant record pair the coordination service's live role-change
//! endpoint produces for a downgrade (a plain Revoke, bumping the group's
//! `auth_epoch`, immediately followed by a Grant at the new, lower role).
//!   (f) an Editor-granted device's session is proven live (a real edit
//!       syncs normally), then downgraded to Viewer WITHOUT tearing down or
//!       reconnecting either daemon's session -- proven by the exact same
//!       `Arc<PeerSyncSession>` on both sides before and after. A NEW local
//!       edit made after the downgrade becomes authoritative is withheld
//!       exactly like scenario (a)'s from-the-start Viewer, proving the
//!       downgrade closed the window promptly through the existing live
//!       netmap-push mechanism, with no daemon-side code change needed.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::change_policy::WriterRole;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

static TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestDaemon {
    state: Arc<DaemonState>,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the process
    // tears the temp dir down on exit.
    let store = Arc::new(SegmentBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { state }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id,
    };
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, state).await;
    });
}

/// Waits until `state`'s own verified policy chain for `group_id` has
/// reached at least `seq` -- i.e. this device has actually received and
/// verified the real signed grant record(s) `FakeCoordination::grant_role`
/// appended, through its own real netmap subscription, not merely that
/// *some* (possibly still-empty, seq-0) verified state exists.
///
/// Every scenario below waits on this before making its authorization-
/// sensitive move, because `DaemonState::resolve_group_policy` returns
/// `Withhold` (blocking ANY local write, regardless of role) for the whole
/// window between a device being introduced to a group and that group's
/// real policy actually loading. Skipping this wait would make an Editor's
/// legitimate write occasionally flaky (withheld for an unrelated timing
/// reason) and would make a Viewer's withheld write "pass" for the wrong
/// reason on a slow run.
async fn wait_for_group_policy_seq(state: &Arc<DaemonState>, group_id: &str, seq: u64) {
    wait_until(
        || {
            state
                .authority
                .group_policy_state(group_id)
                .map(|policy| policy.current_seq >= seq)
                .unwrap_or(false)
        },
        Duration::from_secs(20),
    )
    .await;
}

/// Common two-device setup shared by all three scenarios: registers device A
/// and device B with the fake coordination plane, grants device B `b_role`
/// for `group_id` through a real signed record, links both devices into the
/// group, starts both real daemons' `peer_orchestrator`s, and waits until
/// their session has handshaked and both sides have verified the real
/// policy chain (see `wait_for_group_policy_seq`'s own doc comment for why
/// the latter matters).
async fn setup_two_devices(
    fake: &FakeCoordination,
    device_a_id: &str,
    device_b_id: &str,
    group_id: &str,
    b_role: WriterRole,
) -> (TestDaemon, TestDaemon, tempfile::TempDir, tempfile::TempDir) {
    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    register_with_fake(fake, &daemon_a.state, device_a_id, &[group_id]).await;
    register_with_fake(fake, &daemon_b.state, device_b_id, &[group_id]).await;
    // Device B's role grant -- a real signed `ACTION_GRANT_WITH_ROLE`
    // record, matching the coordination service's own `recordGrantWithRole`
    // shape. Issued before either daemon's orchestrator connects, so each
    // device's very first netmap frame already carries the full chain.
    fake.grant_role(device_b_id, group_id, b_role);

    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_b.state, root_b.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), daemon_b.state.clone());
    // The peer-session handshake waited on below does NOT imply the
    // reconciliation substrate is reachable -- different socket, different
    // ALPN, and `FakeCoordination` carries only the former. See
    // `support::advertise_substrate_between`.
    support::advertise_substrate_between(&[&daemon_a.state, &daemon_b.state]).await;

    wait_until(|| daemon_a.state.peers.session(device_b_id).is_some(), Duration::from_secs(40))
        .await;
    wait_for_group_policy_seq(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_seq(&daemon_b.state, group_id, 1).await;

    (daemon_a, daemon_b, root_a, root_b)
}

/// Scenario (a): a Viewer-granted device's own local edit, made through the
/// real filesystem-watch pipeline, must never be applied or synced to a
/// peer -- proving the real `local_change_auth_provider` fix
/// (`daemon_state.rs`) actually engages through this real end-to-end
/// pipeline, not just against a synthetic fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn viewer_granted_devices_local_edit_is_withheld_not_applied_or_synced() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-viewer-withheld";
    let device_b_id = "device-b-viewer-withheld";
    let group_id = "group-viewer-withheld";

    let (_daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Viewer).await;

    // Device B (Viewer-only) makes a real local edit through the real
    // filesystem-watch pipeline.
    std::fs::write(root_b.path().join("viewer-edit.txt"), b"must never sync").unwrap();

    // Generous settle window: long enough that any real sync would have
    // completed several times over -- scenario (b) below observes a
    // legitimate sync land well under this bound in the same process.
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Not synced anywhere: the peer never receives it. Under checkpoint
    // admission, local emission is unconditional -- there is no local writer-role gate left
    // to bypass or to independently verify against. The enforcement point
    // moved entirely to checkpoint ISSUANCE: `flush_pending_checkpoint`
    // requests a checkpoint from the coordination plane for B's Pending
    // Change, the plane's own live writer check refuses it (B is a
    // Viewer), and a Change with no checkpoint is never eligible for
    // `send_change_batch` to serve at all -- structurally, not by any
    // runtime rejection A performs. This is what makes the old defense-in-
    // depth "bypass B's local gate, prove A's independent gate still
    // rejects it on receipt" scenario (formerly (c)/(g)/(h) in this file)
    // moot: there is no wire delivery for A to reject in the first place.
    assert!(
        !root_a.path().join("viewer-edit.txt").exists(),
        "a Viewer-granted device's local edit must never sync to a peer"
    );

    // IS applied to device B's own local state: local emission no longer
    // consults writer role at all (see `replica_coordinator.rs`'s
    // `LocalPolicyHeadProvider` doc comment), so the edit lands in B's file
    // index and DAG as an ordinary Pending Change -- it simply never
    // acquires the checkpoint evidence `send_change_batch` requires to
    // publish it.
    let indexed_on_b = daemon_b
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(group_id, "viewer-edit.txt")
        .unwrap();
    assert!(
        indexed_on_b.is_some(),
        "local emission is unconditional under checkpoint admission -- a Viewer's own \
         edit must still be captured locally as a Pending Change, got {indexed_on_b:?}"
    );
}

/// Scenario (b): the identical setup, but device B is granted Editor
/// instead of Viewer -- its local edit must succeed and sync normally. The
/// control/contrast case proving this harness genuinely distinguishes the
/// two roles rather than accidentally testing something that always fails
/// (or always passes) regardless of role.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_granted_devices_local_edit_succeeds_and_syncs_normally() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-editor-control";
    let device_b_id = "device-b-editor-control";
    let group_id = "group-editor-control";

    let (_daemon_a, _daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    std::fs::write(root_b.path().join("editor-edit.txt"), b"editor edits sync normally").unwrap();

    // Waits for the content, not merely for the path to exist: materializing
    // a synced file can create it before its bytes land (a placeholder, or a
    // create-then-write sequence), and a bare `.exists()` wait races that
    // window -- caught as a flake reading back all zeros instead of content.
    let target = root_a.path().join("editor-edit.txt");
    wait_until(
        || std::fs::read(&target).ok().as_deref() == Some(b"editor edits sync normally".as_slice()),
        Duration::from_secs(40),
    )
    .await;
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"editor edits sync normally",
        "an Editor-granted device's local edit must sync to a peer with unchanged content"
    );
}

/// Shared body for scenarios (d)/(e): device B has `role` for `group_id`,
/// and its local disk already holds `pre-existing.txt` BEFORE the group is
/// ever linked -- exactly the state `dag_import::ensure_initial_import`
/// exists to convert into signed history on first link, and the state
/// `backfill_missing_history`'s coverage audit exists to catch if that
/// one-shot import is itself withheld waiting on policy to load. `expect_
/// synced` selects which outcome is asserted: `false` for Viewer (imported
/// locally as Pending, but never syncs), `true` for Editor (imported,
/// checkpointed, and synced normally) -- the control proving this scenario
/// pair genuinely distinguishes the two roles rather than testing something
/// that always passes or always fails regardless of role.
async fn pre_existing_content_initial_import_scenario(role: WriterRole, expect_synced: bool) {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let suffix = if expect_synced { "editor" } else { "viewer" };
    let device_a_id = format!("device-a-preexisting-{suffix}");
    let device_b_id = format!("device-b-preexisting-{suffix}");
    let group_id = format!("group-preexisting-{suffix}");

    let daemon_a = new_test_daemon(&device_a_id);
    let daemon_b = new_test_daemon(&device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    // Content already on B's disk BEFORE the group is linked at all -- the
    // scenario `ensure_initial_import` exists for, distinct from scenarios
    // (a)/(b)'s live watcher edits made AFTER linking.
    std::fs::write(root_b.path().join("pre-existing.txt"), b"already on disk before link").unwrap();

    register_with_fake(&fake, &daemon_a.state, &device_a_id, &[&group_id]).await;
    register_with_fake(&fake, &daemon_b.state, &device_b_id, &[&group_id]).await;
    fake.grant_role(&device_b_id, &group_id, role);

    link(&daemon_a.state, root_a.path(), &group_id);
    link(&daemon_b.state, root_b.path(), &group_id);

    spawn_orchestrator(fake.addr(), device_a_id.clone(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.clone(), daemon_b.state.clone());
    support::advertise_substrate_between(&[&daemon_a.state, &daemon_b.state]).await;

    wait_until(|| daemon_a.state.peers.session(&device_b_id).is_some(), Duration::from_secs(40))
        .await;
    wait_for_group_policy_seq(&daemon_a.state, &group_id, 1).await;
    wait_for_group_policy_seq(&daemon_b.state, &group_id, 1).await;

    if expect_synced {
        // See `editor_granted_devices_local_edit_succeeds_and_syncs_normally`
        // on why this waits for content, not merely for the path to exist.
        let target = root_a.path().join("pre-existing.txt");
        wait_until(
            || {
                std::fs::read(&target).ok().as_deref()
                    == Some(b"already on disk before link".as_slice())
            },
            Duration::from_secs(40),
        )
        .await;
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"already on disk before link",
            "an Editor-granted device's pre-existing content must import and sync to a peer with \
             unchanged content"
        );
        assert_eq!(
            support::native_group_head_set(&daemon_b.state, &group_id).len(),
            1,
            "an Editor-granted device's initial import must commit exactly one head locally"
        );
    } else {
        // Generous settle window: long enough that any real import+sync
        // would have completed several times over -- the Editor variant of
        // this same scenario observes it land well under this bound.
        tokio::time::sleep(Duration::from_secs(8)).await;

        assert!(
            !root_a.path().join("pre-existing.txt").exists(),
            "a Viewer-granted device's pre-existing content must never sync to a peer"
        );
        // Local emission is unconditional under checkpoint admission --
        // the import still lands locally as an ordinary
        // Pending head; only checkpoint issuance (and thus sync to A)
        // is withheld.
        assert_eq!(
            support::native_group_head_set(&daemon_b.state, &group_id).len(),
            1,
            "local emission is unconditional -- a Viewer-granted device's pre-existing content \
             must still be committed to its own local signed change history as a Pending head"
        );
    }
}

/// Scenario (d): a Viewer-granted device's pre-existing local content (on
/// disk before the group is ever linked) is captured locally as a Pending
/// Change by the initial-import/coverage-backfill path, but must never sync
/// to a peer -- proving the shared checkpoint-issuance gate that scenario
/// (a) proves for the live watcher path also covers this separate
/// construction path through the real production pipeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn viewer_granted_devices_pre_existing_content_initial_import_is_withheld() {
    pre_existing_content_initial_import_scenario(WriterRole::Viewer, false).await;
}

/// Scenario (e): the identical setup, but device B is granted Editor
/// instead of Viewer -- its pre-existing content imports and syncs
/// normally. The control/contrast case proving scenario (d) genuinely
/// distinguishes the two roles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_granted_devices_pre_existing_content_initial_import_succeeds() {
    pre_existing_content_initial_import_scenario(WriterRole::Editor, true).await;
}

/// Waits until `state`'s own verified policy chain for `group_id` reflects a
/// downgrade -- `writers_up_to`/`current_writers` exclude Viewers, so
/// `current_seq` alone (as `wait_for_group_policy_seq` checks) cannot tell
/// "downgraded" apart from "not caught up yet" for a device this daemon
/// itself has no writer-set visibility into from outside; polling the
/// device's own `current_epoch` instead is unambiguous, since only a
/// Revoke (this downgrade's own chained first record) ever bumps it.
async fn wait_for_group_policy_epoch(state: &Arc<DaemonState>, group_id: &str, epoch: u64) {
    wait_until(
        || {
            state
                .authority
                .group_policy_state(group_id)
                .map(|policy| policy.current_epoch >= epoch)
                .unwrap_or(false)
        },
        Duration::from_secs(20),
    )
    .await;
}

/// Scenario (f): the security property that a live role downgrade must
/// invalidate an already-established, currently-connected session's write
/// privileges promptly, without requiring a reconnect. Device B starts as a
/// genuine Editor with a real, already-connected, already-productive
/// session to device A (proven by a real edit syncing first) -- then gets
/// downgraded to Viewer via `FakeCoordination::downgrade_role`'s chained
/// Revoke-then-Grant, WITHOUT either daemon's `peer_orchestrator` ever being
/// restarted or its session torn down and reconnected (proven directly by
/// `Arc::ptr_eq` on the exact same `PeerSyncSession` object on both sides,
/// before and after). A brand-new local edit made only after the downgrade
/// becomes authoritative (this device's own verified policy epoch has
/// advanced) must be withheld exactly like scenario (a)'s from-the-start
/// Viewer -- proving the existing live netmap-push mechanism
/// (`record_group_policy_states` re-run on every netmap frame,
/// `local_change_auth_provider`'s per-emission re-check against the
/// freshest verified policy) already closes the "stale session keeps
/// operating under old privileges" gap on its own, with no daemon-side
/// production code change required for this to hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_downgraded_to_viewer_mid_session_cannot_author_accepted_changes_without_reconnecting(
) {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-live-downgrade";
    let device_b_id = "device-b-live-downgrade";
    let group_id = "group-live-downgrade";

    let (daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    // Prove the session is genuinely live and productive as an Editor
    // BEFORE the downgrade -- the control that distinguishes "the downgrade
    // closed a real, working privilege" from "nothing was ever working
    // anyway".
    std::fs::write(root_b.path().join("before-downgrade.txt"), b"editor edit, pre-downgrade")
        .unwrap();
    // See `editor_granted_devices_local_edit_succeeds_and_syncs_normally` on
    // why this waits for content, not merely for the path to exist.
    let before_downgrade_target = root_a.path().join("before-downgrade.txt");
    wait_until(
        || {
            std::fs::read(&before_downgrade_target).ok().as_deref()
                == Some(b"editor edit, pre-downgrade".as_slice())
        },
        Duration::from_secs(40),
    )
    .await;
    assert_eq!(std::fs::read(&before_downgrade_target).unwrap(), b"editor edit, pre-downgrade");

    // Snapshot both directions' session objects before the downgrade, to
    // later prove neither daemon reconnected because of it.
    let session_b_to_a_before = daemon_b
        .state
        .peers
        .session(device_a_id)
        .expect("device B must have a live session to device A before the downgrade");
    let session_a_to_b_before = daemon_a
        .state
        .peers
        .session(device_b_id)
        .expect("device A must have a live session to device B before the downgrade");

    // The downgrade itself: chained Revoke (bumps auth_epoch) + Grant at
    // Viewer, pushed over the SAME live netmap subscription both daemons
    // already hold open -- no daemon restart, no new connection.
    fake.downgrade_role(device_b_id, group_id, WriterRole::Viewer);

    // Wait for BOTH daemons' own verified policy state to actually observe
    // the downgrade (not merely for the push to have been sent) -- this is
    // the same real, verified-chain-driven authorization state
    // `local_change_auth_provider` (on B) and `accepts_change_auth` (on A)
    // each independently consult.
    wait_for_group_policy_epoch(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_epoch(&daemon_b.state, group_id, 1).await;

    // Neither session was torn down and reconnected by the downgrade --
    // this is the literal "already-established session", not a fresh one
    // that merely happens to see the new role on its first connect.
    let session_b_to_a_after = daemon_b
        .state
        .peers
        .session(device_a_id)
        .expect("device B's session to device A must still be live after the downgrade");
    let session_a_to_b_after = daemon_a
        .state
        .peers
        .session(device_b_id)
        .expect("device A's session to device B must still be live after the downgrade");
    assert!(
        Arc::ptr_eq(&session_b_to_a_before, &session_b_to_a_after),
        "the downgrade must not tear down and reconnect device B's session -- this test proves an \
         IN-FLIGHT session is invalidated, not merely a future reconnection"
    );
    assert!(
        Arc::ptr_eq(&session_a_to_b_before, &session_a_to_b_after),
        "the downgrade must not tear down and reconnect device A's session either"
    );

    // The actual security assertion: a NEW local edit, made only after the
    // downgrade became authoritative, over the SAME still-connected session.
    std::fs::write(root_b.path().join("after-downgrade.txt"), b"must never sync post-downgrade")
        .unwrap();

    // Same generous settle window scenario (a) uses.
    tokio::time::sleep(Duration::from_secs(8)).await;

    assert!(
        !root_a.path().join("after-downgrade.txt").exists(),
        "a device downgraded to Viewer mid-session must never sync a NEW edit made after the \
         downgrade became authoritative, without needing to reconnect first"
    );
    let indexed_on_b = daemon_b
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(group_id, "after-downgrade.txt")
        .unwrap();
    assert!(
        indexed_on_b.is_some(),
        "local emission is unconditional under checkpoint admission -- the downgraded \
         device's post-downgrade edit must still be captured locally as a Pending Change, got \
         {indexed_on_b:?}"
    );
}

/// content must simply remain exactly as synced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downgraded_devices_pre_downgrade_history_remains_valid_retained_history() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-retained-history-ok";
    let device_b_id = "device-b-retained-history-ok";
    let group_id = "group-retained-history-ok";

    let (daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    // A genuine, legitimately-authored Editor edit, synced before any
    // downgrade -- this is the retained history the fix must never
    // quarantine.
    std::fs::write(root_b.path().join("legitimate-before-downgrade.txt"), b"legitimately authored")
        .unwrap();
    // See `editor_granted_devices_local_edit_succeeds_and_syncs_normally` on
    // why this waits for content, not merely for the path to exist.
    let legitimate_target = root_a.path().join("legitimate-before-downgrade.txt");
    wait_until(
        || {
            std::fs::read(&legitimate_target).ok().as_deref()
                == Some(b"legitimately authored".as_slice())
        },
        Duration::from_secs(40),
    )
    .await;
    assert_eq!(std::fs::read(&legitimate_target).unwrap(), b"legitimately authored");

    fake.downgrade_role(device_b_id, group_id, WriterRole::Viewer);
    wait_for_group_policy_epoch(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_epoch(&daemon_b.state, group_id, 1).await;

    // The already-synced content must remain exactly as it was -- the
    // downgrade must not roll back or remove anything already legitimately
    // admitted.
    assert!(
        root_a.path().join("legitimate-before-downgrade.txt").exists(),
        "a downgrade must never remove or roll back content that was legitimately synced BEFORE \
         the downgrade"
    );
    assert_eq!(
        std::fs::read(root_a.path().join("legitimate-before-downgrade.txt")).unwrap(),
        b"legitimately authored"
    );

    // Keep both daemons' roots/orchestrators alive for the whole test.
    let _ = (&daemon_a, &daemon_b, &root_b);
}

/// Scenario (i): the convergence failure the freshness floor caused, and the
/// relay exemption closes -- proven through this same full production stack.
///
/// The floor requires a Change's AUTHOR to still be a current writer at the
/// receiver's verified policy state. Applied to every delivery, including one
/// where a trusted peer is honestly relaying somebody else's already-signed
/// history, it makes a downgraded device's legitimately pre-downgrade work
/// permanently undeliverable to any peer that does not already hold it: the
/// author will never be a current writer again, and no other device was ever
/// allowed to speak for it. That is silent, needs no attacker, and hits the
/// ordinary cases -- a new device joining, a device returning after a long
/// absence, a full-replica handoff target.
///
/// The scenario: an Editor authors a file and syncs it to a second Editor,
/// so it is genuine, admitted history on that peer. The author is then
/// downgraded to Viewer and goes offline, closing its network endpoint, so
/// delivery to the third device is unambiguously a relay and cannot have
/// come from the author itself. A third device joins fresh as an Editor and
/// must still converge on the author's pre-downgrade file, obtained entirely
/// from the relaying peer.
///
/// Offline, not merely hidden: a downgraded author is still a group member,
/// so every other member is still authorized to connect to it, and a peer
/// session opens wherever the network reaches it -- including by local-network
/// discovery, which finds a device on the same host no matter what endpoints
/// the coordination plane lists for it.
///
/// Note what is NOT relaxed: the author is still a Viewer everywhere, and
/// scenario (h) above -- which must stay green, unmodified -- proves the same
/// author pushing its OWN Change under that same stale pin is still refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_downgraded_authors_pre_downgrade_history_still_reaches_a_newly_joined_device() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let author_id = "device-author-relay-catchup";
    let relay_id = "device-relay-catchup";
    let joiner_id = "device-joiner-relay-catchup";
    let group_id = "group-relay-catchup";

    let daemon_author = new_test_daemon(author_id);
    let daemon_relay = new_test_daemon(relay_id);
    let root_author = tempfile::tempdir().unwrap();
    let root_relay = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_author.state, author_id, &[group_id]).await;
    register_with_fake(&fake, &daemon_relay.state, relay_id, &[group_id]).await;
    fake.grant_role(author_id, group_id, WriterRole::Editor);
    fake.grant_role(relay_id, group_id, WriterRole::Editor);

    link(&daemon_author.state, root_author.path(), group_id);
    link(&daemon_relay.state, root_relay.path(), group_id);
    spawn_orchestrator(fake.addr(), author_id.to_string(), daemon_author.state.clone());
    spawn_orchestrator(fake.addr(), relay_id.to_string(), daemon_relay.state.clone());
    support::advertise_substrate_between(&[&daemon_author.state, &daemon_relay.state]).await;

    wait_until(|| daemon_author.state.peers.session(relay_id).is_some(), Duration::from_secs(40))
        .await;
    wait_for_group_policy_seq(&daemon_author.state, group_id, 2).await;
    wait_for_group_policy_seq(&daemon_relay.state, group_id, 2).await;

    // A genuine Editor edit, authored and synced BEFORE any downgrade. This
    // is the legitimate history the fix must keep deliverable.
    std::fs::write(root_author.path().join("pre-downgrade.txt"), b"authored while an editor")
        .unwrap();
    // See `editor_granted_devices_local_edit_succeeds_and_syncs_normally` on
    // why this waits for content, not merely for the path to exist.
    let relay_target = root_relay.path().join("pre-downgrade.txt");
    wait_until(
        || {
            std::fs::read(&relay_target).ok().as_deref()
                == Some(b"authored while an editor".as_slice())
        },
        Duration::from_secs(40),
    )
    .await;
    assert_eq!(
        std::fs::read(&relay_target).unwrap(),
        b"authored while an editor",
        "the relaying peer must genuinely hold the author's pre-downgrade content before the \
         downgrade -- otherwise there is nothing for it to relay and this scenario proves nothing"
    );

    // The downgrade. The author stays a group MEMBER (a Viewer still reads),
    // so the joining device below still pins its signing key from the netmap
    // and can verify its signature -- exactly the real-world shape.
    fake.grant_role(author_id, group_id, WriterRole::Viewer);
    wait_for_group_policy_seq(&daemon_author.state, group_id, 3).await;
    wait_for_group_policy_seq(&daemon_relay.state, group_id, 3).await;

    // The author goes offline before the third device exists, so any Change
    // of the author's that reaches the joiner demonstrably came from the
    // relaying peer. Closing the endpoint is what makes it unreachable: the
    // author is still a member the joiner is authorized to connect to, and
    // local-network discovery would otherwise find it on this host whatever
    // endpoints the coordination plane lists.
    daemon_author
        .state
        .peer_session_driver()
        .expect("the author's orchestrator has started its peer session driver")
        .stack()
        .shutdown()
        .await;

    // The third device joins fresh, AFTER the downgrade is authoritative.
    let daemon_joiner = new_test_daemon(joiner_id);
    let root_joiner = tempfile::tempdir().unwrap();
    register_with_fake(&fake, &daemon_joiner.state, joiner_id, &[group_id]).await;
    fake.grant_role(joiner_id, group_id, WriterRole::Editor);

    link(&daemon_joiner.state, root_joiner.path(), group_id);
    spawn_orchestrator(fake.addr(), joiner_id.to_string(), daemon_joiner.state.clone());
    // Only relay<->joiner: the author is offline, and the scenario is that
    // the Change arrives THROUGH the relay.
    support::advertise_substrate_between(&[&daemon_relay.state, &daemon_joiner.state]).await;

    wait_until(|| daemon_joiner.state.peers.session(relay_id).is_some(), Duration::from_secs(40))
        .await;
    wait_for_group_policy_seq(&daemon_joiner.state, group_id, 4).await;
    // The relaying peer must be caught up too, not merely connected. A relay
    // BEHIND the receiver on this group's policy chain is deliberately
    // refused the relay exemption (that is what stops an honest-but-stale
    // relay laundering a forgery), so waiting here is what makes this
    // scenario about the exemption rather than about how fast the two
    // devices' netmaps happened to converge. It self-heals either way --
    // anti-entropy re-delivers once the relay catches up -- but waiting
    // keeps the failure mode legible.
    wait_for_group_policy_seq(&daemon_relay.state, group_id, 4).await;

    // The assertion this whole scenario exists for. See
    // `editor_granted_devices_local_edit_succeeds_and_syncs_normally` on why
    // this waits for content, not merely for the path to exist.
    let joiner_target = root_joiner.path().join("pre-downgrade.txt");
    wait_until(
        || {
            std::fs::read(&joiner_target).ok().as_deref()
                == Some(b"authored while an editor".as_slice())
        },
        Duration::from_secs(60),
    )
    .await;
    assert_eq!(
        std::fs::read(&joiner_target).unwrap(),
        b"authored while an editor",
        "a newly-joined device must converge on a since-downgraded author's legitimately \
         pre-downgrade history, relayed by a current-writer peer -- without the relay exemption \
         this content can never reach it from anyone, because its author will never be a current \
         writer again"
    );

    // And it really was a relay: the joiner never established a session with
    // the author at all.
    assert!(
        daemon_joiner.state.peers.session(author_id).is_none(),
        "the joining device must never have handshaked with the downgraded author -- otherwise \
         this test could have passed on a direct delivery and would prove nothing about relayed \
         history"
    );

    let _ = (&daemon_author, &daemon_relay, &root_author);
}
