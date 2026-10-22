//! C2 hardening: `restore_to_version` was only ever tested as a
//! single-daemon control-socket round trip
//! (`control_socket.rs::list_versions_then_restore_version_round_trips_
//! through_control_socket`) -- never against a real second peer. This
//! file closes the two gaps this project's own C2 survey flagged:
//!
//! 1. A restore authored on one device must propagate to a connected
//!    peer over the real P2P protocol, exactly like an ordinary edit.
//! 2. A restore racing an ordinary concurrent edit on the same path must
//!    resolve deterministically -- both devices independently agreeing
//!    on the same outcome -- via the SAME version-vector conflict
//!    machinery an edit-vs-edit race already uses, with no
//!    restore-specific special-casing (see `hydration::restore_to_
//!    version`'s own doc comment, which states this is exactly the
//!    design intent).
//!
//! Both scenarios wait on each device's own DAG-indexed current
//! version, not merely on-disk file content: a filesystem write lands
//! synchronously, but the watcher's debounced capture into an authored
//! DAG change (the thing `restore_to_version`'s own `version_seq`
//! argument and the conflict-resolution race actually operate on) can
//! still be in flight for a moment afterward. A content-only wait can
//! therefore return before that capture completes, letting a restore
//! target a `version_seq` that doesn't exist yet, or letting the
//! "concurrent" race start before one side has actually authored
//! anything.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{open_file_backed_replica_coordinator, real_entry_names, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::VersionState;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

fn setup_device(name: &str) -> TestDevice {
    let device_id = name.to_string();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.clone(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

fn snapshot(root: &std::path::Path) -> std::collections::HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| (name.clone(), std::fs::read_to_string(root.join(&name)).unwrap_or_default()))
        .collect()
}

/// Waits until `device`'s own DAG has genuinely indexed `path`'s current
/// version as exactly `expected_version_seq` -- unlike a disk-content
/// wait, this is what proves the local watcher's debounced capture has
/// actually finished authoring the change, not merely that the bytes
/// landed on disk a moment ago.
async fn wait_for_current_version(
    device: &TestDevice,
    group_id: &str,
    path: &str,
    expected_version_seq: i64,
) {
    wait_until_with_context(
        || {
            device
                .state
                .replica_coordinator
                .sqlite()
                .dag_list_versions(group_id, path)
                .unwrap_or_default()
                .iter()
                .any(|v| v.state == VersionState::Current && v.version_seq == expected_version_seq)
        },
        Duration::from_secs(30),
        || {
            format!(
                "{} never indexed version_seq={expected_version_seq} as current for {path}: {:?}",
                device.device_id,
                device.state.replica_coordinator.sqlite().dag_list_versions(group_id, path)
            )
        },
    )
    .await;
}

/// The `version_seq` of `path`'s current version on `device`.
fn current_version_seq(device: &TestDevice, group_id: &str, path: &str) -> i64 {
    device
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)
        .unwrap()
        .iter()
        .find(|v| v.state == VersionState::Current)
        .map(|v| v.version_seq)
        .expect("a current version")
}

/// N1 (restore, real second peer): A authors a restore back to an old
/// version; B, a connected real peer, must converge on that restored
/// content over the actual P2P protocol -- never previously exercised
/// beyond a single-daemon control-socket round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_version_propagates_to_a_connected_peer() {
    support::ensure_isolated_config_dir();

    let a = setup_device("device-a");
    let b = setup_device("device-b");
    let group_id = "restore-propagation-group";
    start_watching(&a, group_id);
    start_watching(&b, group_id);
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&group_id.to_string()),
    )
    .await;

    std::fs::write(a.root.path().join("doc.txt"), "version one").unwrap();
    wait_for_current_version(&a, group_id, "doc.txt", 1).await;
    std::fs::write(a.root.path().join("doc.txt"), "version two").unwrap();
    wait_for_current_version(&a, group_id, "doc.txt", 2).await;

    wait_until_with_context(
        || {
            std::fs::read_to_string(b.root.path().join("doc.txt")).unwrap_or_default()
                == "version two"
        },
        Duration::from_secs(60),
        || format!("B never converged on A's second write: {:?}", real_entry_names(b.root.path())),
    )
    .await;

    // Restore A back to the first version -- version_seq 1, confirmed
    // above to genuinely exist in A's own DAG by this point.
    hydration::restore_to_version(&a.state, group_id, "doc.txt", 1).await.unwrap();

    wait_until_with_context(
        || {
            std::fs::read_to_string(a.root.path().join("doc.txt")).unwrap_or_default()
                == "version one"
        },
        Duration::from_secs(10),
        || {
            format!(
                "A's own restore never materialized locally: {:?}",
                real_entry_names(a.root.path())
            )
        },
    )
    .await;

    wait_until_with_context(
        || {
            std::fs::read_to_string(b.root.path().join("doc.txt")).unwrap_or_default()
                == "version one"
        },
        Duration::from_secs(60),
        || {
            format!(
                "B never converged on A's restore -- B still reads {:?}",
                std::fs::read_to_string(b.root.path().join("doc.txt"))
            )
        },
    )
    .await;
}

/// N1 (restore, concurrency): a restore on one device racing an ordinary
/// edit on another, both touching the same path, must resolve
/// deterministically -- both devices independently agreeing on the
/// identical outcome, exactly like an ordinary edit-vs-edit race already
/// does (`three_way_concurrent_edit_conflict.rs`). Proves
/// `restore_to_version`'s own doc comment claim that a restore carries
/// no special-cased conflict behavior of its own.
///
/// Genuinely concurrent, not merely unstaggered: the peers are
/// disconnected before each side authors its own change, so A's restore
/// and B's edit are each captured into their own local DAG independent
/// of the other (real causal concurrency, a version-vector fork) --
/// reconnecting afterward is what forces the SAME conflict-resolution
/// machinery an edit-vs-edit race already exercises to actually run,
/// rather than one side merely adopting the other's change first because
/// it arrived before the race began.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_racing_a_concurrent_edit_converges_deterministically() {
    support::ensure_isolated_config_dir();

    let a = setup_device("device-a");
    let b = setup_device("device-b");
    let group_id = "restore-race-group";
    start_watching(&a, group_id);
    start_watching(&b, group_id);
    let handles = support::connect_two_daemons_with_handles(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&group_id.to_string()),
    )
    .await;

    std::fs::write(a.root.path().join("doc.txt"), "version one").unwrap();
    wait_for_current_version(&a, group_id, "doc.txt", 1).await;
    std::fs::write(a.root.path().join("doc.txt"), "version two").unwrap();
    wait_for_current_version(&a, group_id, "doc.txt", 2).await;
    // Everything below needs B to receive A's second write over its existing
    // file, then a winner replacing a loser's original: both need durable
    // namespace changes.
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "B receiving A's second write and the conflict winner replacing the original",
    ) {
        return;
    }
    wait_until_with_context(
        || {
            std::fs::read_to_string(b.root.path().join("doc.txt")).unwrap_or_default()
                == "version two"
        },
        Duration::from_secs(60),
        || format!("B never converged on A's second write: {:?}", real_entry_names(b.root.path())),
    )
    .await;
    // B may have received only the latest of A's writes, so its own numbering of
    // the path's versions is its own: what it has to author next is one above
    // wherever it stands.
    let b_seq = current_version_seq(&b, group_id, "doc.txt");

    // Disconnect -- each side now authors its own change with no way for
    // the other to see or adopt it yet, a real causal fork. Aborting the
    // `PeerSyncSession` handles alone does not achieve that under the
    // iroh-only reconciliation stack: changes converge over the
    // reconciliation substrate now, independent of those sessions, so
    // `sever_reconciliation` is required too (see its own doc comment) --
    // without it A's restore reaches B before B ever authors its own
    // edit, and the two changes never actually race.
    for handle in handles {
        handle.abort();
    }
    // The sessions are not the only link: reconciliation runs on its own
    // stack, and left up it delivers A's restore to B before B's edit is
    // captured, so the race below would not be concurrent at all.
    support::sever_reconciliation(&a.state, &b.state).await;

    hydration::restore_to_version(&a.state, group_id, "doc.txt", 1).await.unwrap();
    wait_for_current_version(&a, group_id, "doc.txt", 3).await;

    std::fs::write(b.root.path().join("doc.txt"), "concurrent edit from b").unwrap();
    wait_for_current_version(&b, group_id, "doc.txt", b_seq + 1).await;

    // Reconnect -- only now do the two independently-authored histories
    // actually meet, forcing genuine conflict resolution.
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&group_id.to_string()),
    )
    .await;

    // Whichever side the deterministic tiebreak favors, both devices
    // must reach the IDENTICAL final state (either a lone winner at
    // "doc.txt" or a winner plus a deterministically-named conflict
    // copy) -- never a divergence between what A and B each believe
    // happened. Content-based (not just entry-name-based), and requires
    // more than one file at some point during resolution never having
    // been observed as a stale pre-race single-entry snapshot: exactly
    // two authored changes are in the DAG (A's restore, B's edit), so
    // the converged directory holds either one winning entry or one
    // winner plus one conflict copy -- never the pre-race single
    // "version two" file alone.
    wait_until_with_context(
        || {
            let a_snap = snapshot(a.root.path());
            let b_snap = snapshot(b.root.path());
            !a_snap.is_empty() && a_snap == b_snap && a_snap.values().any(|c| c != "version two")
        },
        Duration::from_secs(60),
        || {
            format!(
                "device-a={:?}; device-b={:?}",
                real_entry_names(a.root.path()),
                real_entry_names(b.root.path())
            )
        },
    )
    .await;
}
