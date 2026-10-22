//! A genuine "device goes offline (paused), both sides independently
//! diverge, device comes back online" matrix — a scenario shape no
//! existing chaos/matrix test actually exercises.
//! `monkey_chaos.rs`, `taguchi_collision_matrix.rs`, and
//! `collision_matrix.rs` all race real-time concurrent operations between
//! two devices that stay connected the whole time; none of them ever calls
//! `set_paused` to make one device genuinely stop sending *and receiving*
//! while the other keeps changing files on its own.
//!
//! Two mechanics this file depends on, confirmed by reading the production
//! code rather than assumed:
//!
//! 1. `SyncState::set_paused` is a full two-way gate, not outbound-only —
//!    `peer_session.rs`'s `reconcile_files_if_authorized` checks
//!    `is_paused_for_group` *before* any incoming `FullIndex`/`IndexUpdate`
//!    is reconciled, so a paused device also ignores whatever a still-online
//!    peer sends it during the pause window. That message is dropped, not
//!    queued — there is no redelivery-on-unpause.
//! 2. Because of (1), `LinkRuntimeController::resume` on *just* the
//!    previously-paused device is not sufficient to converge these
//!    scenarios, unlike `e2e_three_devices.rs`'s pause/resume test (whose
//!    online device never changes anything during the pause window, so it
//!    never needs to re-send anything). Here the still-online device's
//!    changes were broadcast *while the peer was paused* and silently
//!    dropped on arrival; nothing re-sends them automatically short of that
//!    device's own ~90s periodic full-index resync
//!    (`peer_session::DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`), far too slow for
//!    a test. So every reconnect below calls `resume_link` on *both*
//!    devices — a harmless no-op on the never-paused side as far as pause
//!    state goes, but it forces that device to (re-)broadcast its current
//!    full index too, which is what actually makes the peer's dropped
//!    changes visible. This mirrors what a real transport-level reconnect
//!    (a fresh `PeerSyncSession::run`, which sends a full index at startup)
//!    would do for both ends; our in-process harness never tears down the
//!    session itself, only the application-level pause gate, so we trigger
//!    the equivalent resync explicitly.
//!
//! `TestDevice`/`setup_device`/`start_watching`/`two_synced_devices` are
//! intentionally self-contained rather than shared — matches this codebase's
//! existing convention of self-contained daemon integration test binaries.

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use support::{
    open_file_backed_replica_coordinator, real_entry_names, wait_until, wait_until_with_context,
    TestAccount,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // File-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see open_file_backed_replica_coordinator's
    // doc comment. Held only to keep the backing temp file alive for the test's
    // duration.
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate. A key set
    // after `start_link_watch` would leave emission off and nothing would sync.
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

/// Sets up two devices, both syncing a fresh folder group, and waits for
/// peer sessions to establish. Every scenario below starts from this.
async fn two_synced_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "partition-matrix-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    start_watching(&device_a, &group_id).await;
    start_watching(&device_b, &group_id).await;

    support::connect_two_daemons(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&group_id),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    (device_a, device_b, group_id)
}

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

/// A device's real (non-artifact) entries as a name→content map. Plain content
/// (not a hash) so a failing assertion's message is directly readable, and a
/// map (not an ordered `Vec` of names) so equality is order-independent
/// *and* catches the "same conflict-copy name on both sides but different
/// content" class of bug — exactly the mismatch `three_way_concurrent_edit_
/// conflict.rs` was written to guard against — that a bare name-set match
/// silently passes through.
fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

/// Waits for both devices to hold the identical name→content snapshot, polling
/// for a stable match rather than a single point-in-time comparison. Compares
/// full content, not just the file-name set: several scenarios below reach an
/// equal *name* set (e.g. both sides holding `shared.txt`) before the winning
/// content has actually propagated, so a name-only wait can return prematurely
/// and race the real conflict resolution.
async fn wait_for_convergence(a: &TestDevice, b: &TestDevice, timeout: Duration) {
    wait_until_with_context(
        || snapshot(a.root.path()) == snapshot(b.root.path()),
        timeout,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(a.root.path()),
                real_entry_names(b.root.path())
            )
        },
    )
    .await;
}

/// Waits until `device` has finished materializing the peer's `path`: it is on
/// disk AND its materialization row has settled to `Present`. The file shows
/// up on disk before the row leaves `Hydrating`, and a removal observed in that
/// window is the daemon's own (not a user delete), so a test that deletes or
/// edits straight after the bare `exists()` races the hydration commit and
/// loses its change.
async fn wait_until_materialized(device: &TestDevice, group_id: &str, path: &str) {
    wait_until_with_context(
        || {
            device.root.path().join(path).exists()
                && device
                    .state
                    .replica_coordinator
                    .materialization_state_repository()
                    .get_materialization_state(group_id, path)
                    .ok()
                    .flatten()
                    == Some(yadorilink_replica_domain::session_state::MaterializationState::Present)
        },
        Duration::from_secs(30),
        || {
            format!(
                "on_disk={} materialization={:?}",
                device.root.path().join(path).exists(),
                device
                    .state
                    .replica_coordinator
                    .materialization_state_repository()
                    .get_materialization_state(group_id, path)
            )
        },
    )
    .await;
}

fn pause(device: &TestDevice) {
    device
        .state
        .replica_coordinator
        .link_repository()
        .set_paused(device.root.path().to_str().unwrap(), true)
        .unwrap();
}

/// Reconnects both devices — see this file's header doc comment for why
/// `resume_link` must be called on *both* sides (not just the one that was
/// actually paused) for a still-online peer's offline-window changes to
/// ever reach the other side.
async fn reconnect_both(a: &TestDevice, b: &TestDevice) {
    LinkRuntimeController::new(a.state.clone())
        .resume(a.root.path().to_str().unwrap())
        .await
        .unwrap();
    LinkRuntimeController::new(b.state.clone())
        .resume(b.root.path().to_str().unwrap())
        .await
        .unwrap();
}

/// Waits until `device`'s own index reflects a locally-processed (not just
/// disk-written) live edit at `path` — i.e. the record exists, isn't a
/// tombstone, and this device's own version-vector entry has been
/// incremented. Same rationale as `e2e_three_devices.rs`'s equivalent
/// inline wait: local-change debouncing means a write isn't indexed
/// synchronously the instant the raw filesystem event fires.
async fn wait_for_local_edit_indexed(device: &TestDevice, group_id: &str, path: &str) {
    wait_until(
        || {
            device
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(group_id, path)
                .ok()
                .flatten()
                .map(|r| !r.deleted)
                .unwrap_or(false)
                && current_version_seq(device, group_id, path) > 0
        },
        Duration::from_secs(15),
    )
    .await;
}

/// Like `wait_for_local_edit_indexed`, but for a local delete: waits until
/// `device`'s own index has recorded a tombstone (with this device's own
/// version-vector increment) at `path`.
async fn wait_for_local_delete_indexed(device: &TestDevice, group_id: &str, path: &str) {
    wait_until_with_context(
        || {
            device
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(group_id, path)
                .ok()
                .flatten()
                .map(|r| r.deleted)
                .unwrap_or(false)
        },
        Duration::from_secs(15),
        || {
            format!(
                "on_disk={} record={:?}",
                device.root.path().join(path).exists(),
                device.state.replica_coordinator.file_index_repository().get_file(group_id, path)
            )
        },
    )
    .await;
}

/// Returns the current retained `version_seq` for `path` — the per-path
/// monotonic counter that replaced the per-device version vector, used as the
/// baseline for `wait_for_local_edit_indexed_past` below.
fn current_version_seq(device: &TestDevice, group_id: &str, path: &str) -> i64 {
    device
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)
        .ok()
        .and_then(|versions| versions.first().map(|v| v.version_seq))
        .unwrap_or(0)
}

fn local_version(device: &TestDevice, group_id: &str, path: &str) -> i64 {
    current_version_seq(device, group_id, path)
}

/// Like `wait_for_local_edit_indexed`, but waits until `device`'s own
/// retained `version_seq` for `path` exceeds `min_version` rather than
/// merely being nonzero. Required whenever the SAME device edits the SAME
/// path more than once within a test: a bare `> 0` check trivially passes
/// on the version already committed by an earlier edit and returns before
/// the later edit has actually been captured/indexed, since local-change
/// debouncing means a write isn't indexed synchronously the instant the
/// raw filesystem event fires. Confirmed root cause (via direct
/// `SyncState` inspection) of this file's own
/// `partition_edit_edit_reconnect_keeps_both_copies_as_original_plus_
/// conflict_copy` and `partition_paused_device_delete_vs_online_device_
/// edit_edit_wins` previously reconnecting before the second edit was
/// actually indexed, silently adopting the peer's version instead of
/// correctly detecting a concurrent edit.
async fn wait_for_local_edit_indexed_past(
    device: &TestDevice,
    group_id: &str,
    path: &str,
    min_version: i64,
) {
    wait_until(
        || {
            device
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(group_id, path)
                .ok()
                .flatten()
                .map(|r| !r.deleted)
                .unwrap_or(false)
                && current_version_seq(device, group_id, path) > min_version
        },
        Duration::from_secs(15),
    )
    .await;
}

// --- Scenario 1: paused device edits, online device edits ------------------

/// Both devices edit the same already-synced file while genuinely
/// disconnected from each other (device B paused, not just racing in real
/// time) — reconnect must produce the same edit-edit-conflict outcome shape
/// as `collision_matrix.rs`'s
/// `concurrent_edit_edit_keeps_both_copies_as_original_plus_conflict_copy`:
/// both copies survive, one under the original name and one as a
/// conflict-marked copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_edit_edit_reconnect_keeps_both_copies_as_original_plus_conflict_copy() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (device_a, device_b, group_id) = two_synced_devices("partition-edit-edit").await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until_materialized(&device_b, &group_id, "shared.txt").await;

    pause(&device_b);

    std::fs::write(device_b.root.path().join("shared.txt"), b"edited offline on B").unwrap();
    wait_for_local_edit_indexed(&device_b, &group_id, "shared.txt").await;

    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    let device_a_baseline = local_version(&device_a, &group_id, "shared.txt");
    std::fs::write(device_a.root.path().join("shared.txt"), b"edited online on A, and longer")
        .unwrap();
    wait_for_local_edit_indexed_past(&device_a, &group_id, "shared.txt", device_a_baseline).await;

    reconnect_both(&device_a, &device_b).await;
    // Deliberately not plain `wait_for_convergence`'s bare snapshot match at
    // rest: both devices already show exactly `["shared.txt"]` (each locally
    // edited, not renamed or deleted) even *before* reconnect, so an
    // equal-snapshot wait could momentarily be satisfied — the same premature-
    // convergence trap `collision_matrix.rs`'s
    // `concurrent_edit_edit_keeps_both_copies_as_original_plus_conflict_
    // copy` documents. Require the conflict-copy artifact to actually exist
    // (`len() > 1`) *and* full name→content agreement between the two sides.
    wait_until_with_context(
        || {
            let a = snapshot(device_a.root.path());
            let b = snapshot(device_b.root.path());
            a.len() > 1 && a == b
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    let names = real_entry_names(device_a.root.path());
    assert!(names.contains(&"shared.txt".to_string()), "{names:?}");
    assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
}

// --- Scenarios 2/3: paused device edits/deletes vs. online device's opposite --

/// Device B edits a file while offline; device A (still online) deletes the
/// same file concurrently. DAG ancestry, not wall-clock order, determines the
/// winner: neither change observed the other, so the load-bearing assertion is
/// that the unobserved edit survives and both replicas converge. Depending on
/// the deterministic `(lamport, change_hash)` tie-break, that content may keep
/// the original path or materialize as a conflict copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_paused_device_edit_vs_online_device_delete_preserves_the_unobserved_edit() {
    let (device_a, device_b, group_id) =
        two_synced_devices("partition-edit-vs-delete-delete-wins").await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until_materialized(&device_b, &group_id, "shared.txt").await;

    pause(&device_b);

    std::fs::write(device_b.root.path().join("shared.txt"), b"edited offline on B, conflict copy")
        .unwrap();
    wait_for_local_edit_indexed(&device_b, &group_id, "shared.txt").await;

    std::fs::remove_file(device_a.root.path().join("shared.txt")).unwrap();
    wait_for_local_delete_indexed(&device_a, &group_id, "shared.txt").await;

    reconnect_both(&device_a, &device_b).await;
    wait_until_with_context(
        || {
            let a = snapshot(device_a.root.path());
            let b = snapshot(device_b.root.path());
            a == b && a.values().any(|content| content == "edited offline on B, conflict copy")
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    let names = real_entry_names(device_a.root.path());
    assert_eq!(names.len(), 1, "the edit must survive exactly once: {names:?}");
    let surviving = device_a.root.path().join(&names[0]);
    assert_eq!(std::fs::read(surviving).unwrap(), b"edited offline on B, conflict copy");
}

/// The reverse roles: device B deletes the file while offline; device A
/// (still online) edits the same file concurrently. Same reasoning as
/// above, mirrored: B's tombstone carries forward the original
/// pre-divergence mtime (B never edited before deleting), strictly older
/// than A's genuinely fresh online edit — the edit wins deterministically,
/// no conflict-copy artifact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_paused_device_delete_vs_online_device_edit_edit_wins() {
    let (device_a, device_b, group_id) =
        two_synced_devices("partition-delete-vs-edit-edit-wins").await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until_materialized(&device_b, &group_id, "shared.txt").await;

    pause(&device_b);

    std::fs::remove_file(device_b.root.path().join("shared.txt")).unwrap();
    wait_for_local_delete_indexed(&device_b, &group_id, "shared.txt").await;

    let device_a_baseline = local_version(&device_a, &group_id, "shared.txt");
    std::fs::write(device_a.root.path().join("shared.txt"), b"edited online on A, survives")
        .unwrap();
    wait_for_local_edit_indexed_past(&device_a, &group_id, "shared.txt", device_a_baseline).await;

    reconnect_both(&device_a, &device_b).await;
    wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

    let names = real_entry_names(device_a.root.path());
    assert_eq!(
        names,
        vec!["shared.txt".to_string()],
        "no conflict-copy artifact expected: {names:?}"
    );
    assert_eq!(
        std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
        b"edited online on A, survives"
    );
}

// --- Scenario 4: paused device deletes, online device deletes ---------------

/// Both devices delete the same already-synced file while genuinely
/// disconnected — no conflict machinery needed (deleted == deleted), no
/// artifact of any kind on either device, same outcome shape as
/// `collision_matrix.rs`'s `concurrent_delete_delete_leaves_no_artifact`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_delete_delete_reconnect_leaves_no_artifact() {
    let (device_a, device_b, group_id) = two_synced_devices("partition-delete-delete").await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until_materialized(&device_b, &group_id, "shared.txt").await;

    pause(&device_b);

    std::fs::remove_file(device_b.root.path().join("shared.txt")).unwrap();
    wait_for_local_delete_indexed(&device_b, &group_id, "shared.txt").await;

    std::fs::remove_file(device_a.root.path().join("shared.txt")).unwrap();
    wait_for_local_delete_indexed(&device_a, &group_id, "shared.txt").await;

    reconnect_both(&device_a, &device_b).await;

    wait_until_with_context(
        || {
            real_entry_names(device_a.root.path()).is_empty()
                && real_entry_names(device_b.root.path()).is_empty()
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    // Settling: nothing resurrects the file afterward.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(real_entry_names(device_a.root.path()).is_empty());
    assert!(real_entry_names(device_b.root.path()).is_empty());
}

// --- Scenario 5: paused device renames, online device edits the old name ---

/// Device B renames an already-synced file while offline (which, per
/// `collision_matrix.rs`'s scenario 5 doc comment, decomposes into an
/// ordinary delete of the old path plus a create of the new one — there is
/// no dedicated `Renamed` `FsChangeKind`); device A (still online)
/// concurrently edits the file under its *old* name.
///
/// This is deliberately a convergence-only assertion, not a specific-winner
/// one: unlike scenarios 2/3 above (a single delete vs. a single edit, whose
/// outcome I traced through `conflict.rs`/`index.rs` with confidence), this
/// scenario layers a second, unrelated local change (a brand-new file at the
/// rename's target path) on top of the same edit-vs-delete race at the old
/// path, and I have not traced whether that second change interacts with
/// conflict resolution at the old path in some way I haven't accounted for.
/// Rather than assert a specific outcome I'm not fully certain of, this
/// checks only that both devices eventually agree on a single identical
/// final state — the property that actually matters for a "did the offline
/// backlog flush correctly" regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_paused_device_rename_vs_online_device_edit_old_name_converges() {
    let (device_a, device_b, group_id) =
        two_synced_devices("partition-rename-vs-edit-old-name").await;

    std::fs::write(device_a.root.path().join("original.txt"), b"base content").unwrap();
    wait_until_materialized(&device_b, &group_id, "original.txt").await;

    pause(&device_b);

    std::fs::rename(
        device_b.root.path().join("original.txt"),
        device_b.root.path().join("renamed-by-b.txt"),
    )
    .unwrap();
    wait_for_local_delete_indexed(&device_b, &group_id, "original.txt").await;
    wait_for_local_edit_indexed(&device_b, &group_id, "renamed-by-b.txt").await;

    std::fs::write(device_a.root.path().join("original.txt"), b"edited on A after B's rename")
        .unwrap();
    wait_for_local_edit_indexed(&device_a, &group_id, "original.txt").await;

    reconnect_both(&device_a, &device_b).await;
    wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

    let names = real_entry_names(device_a.root.path());
    tracing::info!(
        ?names,
        "partition_paused_device_rename_vs_online_device_edit_old_name_converges final state"
    );
    assert!(!names.is_empty(), "{names:?}");
}

// --- Scenario 6: multi-op offline backlog flush -----------------------------

/// The highest-value new scenario this file adds: device B doesn't just
/// make one change while offline, it accumulates a real backlog — creates
/// `x.txt`, edits `x.txt` again, and deletes an already-synced `y.txt` — all
/// while paused. Device A concurrently makes its own conflicting changes to
/// both `x.txt` and `y.txt`. Reconnecting must flush B's entire backlog (not
/// just its most recent change per path) and converge both devices on one
/// identical final state.
///
/// Convergence-only, deliberately: this scenario deliberately layers
/// multiple interacting per-path outcomes (a create/create-shaped race on
/// `x.txt`, an edit/delete-shaped race on `y.txt`) within a single debounced
/// batch flush, specifically to exercise whether the backlog mechanism
/// itself (not just single-file conflict resolution, already covered by
/// scenarios 1-3 above) works — asserting a specific per-file winner here
/// would restate scenarios 1-3's already-covered reasoning while adding risk
/// of a wrong guess about how batching interacts with it; the property that
/// actually matters for this scenario is "did the whole backlog flush and
/// both sides converge," which the assertion below checks directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_multi_op_backlog_flush_converges() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (device_a, device_b, group_id) = two_synced_devices("partition-multi-op-backlog").await;

    std::fs::write(device_a.root.path().join("y.txt"), b"y base").unwrap();
    wait_until_materialized(&device_b, &group_id, "y.txt").await;

    pause(&device_b);

    // B accumulates a real backlog of several ops while offline.
    std::fs::write(device_b.root.path().join("x.txt"), b"x created by B").unwrap();
    wait_for_local_edit_indexed(&device_b, &group_id, "x.txt").await;
    std::fs::write(device_b.root.path().join("x.txt"), b"x edited again by B, and longer").unwrap();
    wait_for_local_edit_indexed(&device_b, &group_id, "x.txt").await;
    std::fs::remove_file(device_b.root.path().join("y.txt")).unwrap();
    wait_for_local_delete_indexed(&device_b, &group_id, "y.txt").await;

    // A independently diverges on the same two paths while B is offline.
    std::fs::write(device_a.root.path().join("x.txt"), b"x created by A, different").unwrap();
    wait_for_local_edit_indexed(&device_a, &group_id, "x.txt").await;
    std::fs::write(device_a.root.path().join("y.txt"), b"y edited by A after base").unwrap();
    wait_for_local_edit_indexed(&device_a, &group_id, "y.txt").await;

    reconnect_both(&device_a, &device_b).await;
    wait_for_convergence(&device_a, &device_b, Duration::from_secs(30)).await;

    let names = real_entry_names(device_a.root.path());
    tracing::info!(?names, "partition_multi_op_backlog_flush_converges final state");
    assert!(names.iter().any(|n| n.starts_with("x")), "{names:?}");
}

// --- Scenario 7: both devices paused simultaneously, resumed at once -------

/// Both devices go offline at the same time, both independently edit the
/// same file, then both are resumed together — racing the reconnect
/// ordering itself (which side's `resume_link` broadcast the other
/// processes first), not just one device's backlog against a peer that was
/// online the whole time. Convergence-only: which copy ends up as the
/// canonical name vs. the conflict copy can depend on exactly this race
/// ordering, which this test intentionally does not control (that's the
/// point of exercising it) — the only property that must hold regardless of
/// ordering is that both devices agree on the same final state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_both_devices_paused_simultaneously_resume_races_converges() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (device_a, device_b, group_id) =
        two_synced_devices("partition-both-paused-simultaneously").await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until_materialized(&device_b, &group_id, "shared.txt").await;

    pause(&device_a);
    pause(&device_b);

    std::fs::write(device_a.root.path().join("shared.txt"), b"edited offline on A").unwrap();
    wait_for_local_edit_indexed(&device_a, &group_id, "shared.txt").await;
    std::fs::write(device_b.root.path().join("shared.txt"), b"edited offline on B, and longer")
        .unwrap();
    wait_for_local_edit_indexed(&device_b, &group_id, "shared.txt").await;

    // Resume both at once, racing the reconnect ordering rather than
    // sequencing it.
    let controller_a = LinkRuntimeController::new(device_a.state.clone());
    let controller_b = LinkRuntimeController::new(device_b.state.clone());
    let (resume_a, resume_b) = tokio::join!(
        controller_a.resume(device_a.root.path().to_str().unwrap()),
        controller_b.resume(device_b.root.path().to_str().unwrap()),
    );
    resume_a.unwrap();
    resume_b.unwrap();

    wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

    let names = real_entry_names(device_a.root.path());
    tracing::info!(
        ?names,
        "partition_both_devices_paused_simultaneously_resume_races_converges final state"
    );
    assert!(names.contains(&"shared.txt".to_string()), "{names:?}");
}
