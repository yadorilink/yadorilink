//! Permanent, generalized regression test superseding the temporary
//! `three_way_conflict_diag.rs` diagnostic.
//!
//! Background: naming a conflict copy from the resolving session's
//! `local_device_id`/`peer_device_id` is correct for a single pairwise
//! resolution, but once a third (or later) device's edit triggers a
//! *second* round of pairwise resolution involving a path that no longer
//! represents this device's own unmediated edit, that naming would
//! misattribute content -- a conflict-copy path embedding one device's id
//! but holding a DIFFERENT device's content. The conflict-copy name must
//! therefore carry the content's true origin device, never whichever peer
//! session happened to process it.
//!
//! This file generalizes that one scenario into a small matrix across
//! device count (3, 4, 5, 6) and write timing (simultaneous vs
//! staggered), all asserting the SAME correctness property the
//! diagnostic checked: after convergence, every device must agree on
//! the exact same (name -> content-hash) map. A "mismatch" bug
//! manifests as devices disagreeing about which name holds which
//! content, NOT merely differing file counts -- so the assertion below
//! compares full snapshots, never just `.len`.
//!
//! Run this file repeatedly (e.g. via a repeated-run script) across the
//! device-count / timing grid to characterize the conflict resolver's
//! convergence behavior. Do not weaken the core assertion to a
//! file-count check -- that would silently hide the exact class of bug
//! this file exists to catch.

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
use support::{
    open_file_backed_replica_coordinator, real_entry_names, wait_until_or_stalled, TestAccount,
};

// A fixed 30s deadline flaked under CI load (macOS/Linux hosted runners can
// spend tens of seconds retrying transient SQLite lock contention -- see
// `directory_conflict_matrix.rs`'s identical rationale) even though
// multi-device convergence was still making progress. Same
// absolute-deadline-plus-stall-detector split used there and in
// `taguchi_collision_matrix.rs`.
//
// Bumped again (120s/30s -> 240s/90s) under checkpoint admission:
// every local edit now needs a real checkpoint-issuance HTTP round trip
// before it can reach a peer at all,
// which a mesh of `device_count` devices pays `device_count` times per
// write -- confirmed genuinely converging, just slower, not stalled: the
// six-device scenarios reliably finished around 90s wall-clock at the OLD
// 30s stall bound before this bump.
const CONVERGENCE_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(240);
const CONVERGENCE_STALL_TIMEOUT: Duration = Duration::from_secs(90);
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

// `TestDevice`/`setup_device`/`start_syncing`/`n_synced_devices` are
// intentionally duplicated from `taguchi_collision_matrix.rs` (and
// friends) rather than shared -- matches this codebase's existing
// convention of self-contained daemon integration test binaries.

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
    // change-DAG emitter is wired and local edits actually propagate. Without
    // this, emission stays off and nothing converges.
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

/// Pairs every device with every other over loopback (a full mesh), the
/// direct-transport stand-in for the coordination-driven peer connections
/// the orchestrator would establish for an authorized group.
async fn connect_mesh(devices: &[TestDevice], group_id: &str) {
    let groups = [group_id.to_string()];
    for i in 0..devices.len() {
        for j in (i + 1)..devices.len() {
            support::connect_two_daemons(
                &devices[i].state,
                &devices[i].device_id,
                &devices[j].state,
                &devices[j].device_id,
                &groups,
            )
            .await;
        }
    }
}

/// One line per device: its DAG frontier, the index rows it holds, and the
/// names actually on disk.
///
/// This is the whole instrumentation for the retroactive-repair liveness
/// defect, and it is deliberately a single snapshot taken once at the
/// moment convergence gives up rather than anything per-poll: the failure
/// is sensitive enough to logging volume that a blanket `debug!` hides it
/// entirely, so the probe must cost nothing until the run has already
/// failed. Three fields separate the three candidate mechanisms without
/// needing to guess between them in advance:
///
/// - frontier differs from a converged device's -> the repair carrier never
///   reached this device at all (a propagation problem, upstream of repair).
/// - frontier equal but the conflict-copy row is absent -> the carrier is in
///   this device's DAG, yet no repair pass ever turned it into an index row.
/// - row present but the name is missing from disk -> it was applied and
///   only materialization never ran.
fn frontier_index_disk_probe(devices: &[TestDevice], group_id: &str) -> String {
    let per_device = devices
        .iter()
        .enumerate()
        .map(|(i, device)| {
            let coordinator = &device.state.replica_coordinator;
            let frontier = match coordinator.sqlite().native_group_heads(group_id) {
                Ok(mut heads) => {
                    heads.sort();
                    heads
                        .iter()
                        .map(|head| hex::encode(head.0)[..8].to_string())
                        .collect::<Vec<_>>()
                }
                Err(error) => vec![format!("heads-error({error})")],
            };
            let index_rows = match coordinator.file_index_repository().list_files(group_id) {
                Ok(files) => {
                    let mut paths = files.iter().map(|file| file.path.clone()).collect::<Vec<_>>();
                    paths.sort();
                    paths
                }
                Err(error) => vec![format!("index-error({error})")],
            };
            format!(
                "device-{i}({}): canonical_heads={frontier:?} \
                 index={index_rows:?} disk={:?}",
                device.device_id,
                real_entry_names(device.root.path())
            )
        })
        .collect::<Vec<_>>()
        .join("\n  ");
    per_device
}

async fn n_synced_devices(n: usize, test_name: &str) -> (Vec<TestDevice>, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "multiway-conflict-group").await;
    for device in &devices {
        support::grant_access(&account, &group_id, &device.device_id).await;
    }
    for device in &devices {
        start_watching(device, &group_id).await;
    }
    connect_mesh(&devices, &group_id).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (devices, group_id)
}

fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read(root.join(&name)).unwrap_or_default();
            (name, hex::encode(sha2::Sha256::digest(&content)))
        })
        .collect()
}

/// Sets up `device_count` real synced devices, has every device write
/// DISTINCT content to the SAME brand-new path with `stagger_ms`
/// between each device's write (0 = back-to-back, no sleep, matching
/// the original diagnostic's "simultaneous" case -- a nonzero stagger
/// gives each write time to propagate and be adopted sequentially
/// rather than racing as a genuine concurrent conflict), waits for
/// genuine (name -> content) convergence, settles briefly, then asserts
/// every device's full (name -> content-hash) snapshot is IDENTICAL to
/// every other device's -- not merely that they have the same file
/// COUNT, since the actual bug is devices disagreeing on which name
/// holds which content.
/// What a row is entitled to assert about the converged result.
///
/// This is a property of the CAUSALITY the row creates, not of its
/// wall-clock stagger, and conflating the two is what made this file look
/// flaky for several rounds. A row whose writes are genuinely concurrent
/// must end with one conflict copy per loser. A row whose writes are
/// genuinely sequential -- each author saw the previous content before
/// editing -- must end with a single winner, because that is ordinary
/// editing, not data loss. Demanding `device_count` entries from the
/// second kind is a bug in the test, and it only ever passed on machines
/// where propagation happened to be slower than the stagger.
#[derive(Clone, Copy, PartialEq, Debug)]
enum ConvergedShape {
    /// Every writer's content survives: the winner plus one conflict copy
    /// per loser.
    EveryWriterSurvives,
    /// Only agreement is asserted. How many entries remain depends on how
    /// many writes actually raced, which depends on the machine.
    ///
    /// Relaxing the count here would, on its own, let the lost-update class
    /// hide: a device silently destroying a peer's content also converges,
    /// and also agrees. What keeps that honest is not this row but
    /// `yadorilink-local-capture`'s
    /// `a_dag_only_peer_admission_between_capture_and_emit_is_not_the_local_
    /// edits_parent`, which pins the same invariant deterministically -- it
    /// sequences capture and emit itself and admits the peer change in
    /// between, with no wall-clock race. That is a strictly stronger guard
    /// than any stagger here could be, because it cannot become
    /// machine-speed-dependent.
    ReplicasAgree,
}

async fn run_multiway_row(
    device_count: usize,
    stagger_ms: u64,
    row_name: &str,
    shape: ConvergedShape,
) {
    let _ = tracing_subscriber::fmt::try_init();
    let (devices, group_id) = n_synced_devices(device_count, row_name).await;
    let stagger = Duration::from_millis(stagger_ms);

    for (i, device) in devices.iter().enumerate() {
        std::fs::write(
            device.root.path().join("shared.bin"),
            format!("device {i} content for {row_name}"),
        )
        .unwrap();
        tracing::info!(device_idx = i, device_id = %device.device_id, row_name, "wrote shared.bin");
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
    }

    // Wait for GENUINE convergence: every device holds the identical
    // name→content-hash map, with all `device_count` conflict-resolved
    // entries present. A name-set-only equality check is satisfied trivially
    // before any content propagates — when every device still holds only its
    // own `shared.bin` — so it would let this convergence test pass without
    // ever exercising conflict resolution. The full-snapshot + expected-count
    // wait below cannot pass until content has actually crossed devices.
    let devices_ref = &devices;
    wait_until_or_stalled(
        || {
            let reference = snapshot(devices_ref[0].root.path());
            let agreed = devices_ref[1..].iter().all(|d| snapshot(d.root.path()) == reference);
            match shape {
                // A name-set-only check would be satisfied trivially before
                // any content crosses devices -- when every device still
                // holds just its own write -- so this row keeps the count.
                ConvergedShape::EveryWriterSurvives => reference.len() == device_count && agreed,
                // Agreement alone, but never on a snapshot so empty it
                // could be satisfied before anything propagated at all.
                ConvergedShape::ReplicasAgree => !reference.is_empty() && agreed,
            }
        },
        || devices_ref.iter().map(|d| snapshot(d.root.path())).collect::<Vec<_>>(),
        CONVERGENCE_ABSOLUTE_TIMEOUT,
        CONVERGENCE_STALL_TIMEOUT,
        || {
            format!(
                "{}\n  {}",
                devices_ref
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                    .collect::<Vec<_>>()
                    .join("; "),
                frontier_index_disk_probe(devices_ref, &group_id)
            )
        },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    for (i, device) in devices.iter().enumerate() {
        let device_ids: Vec<&str> = devices.iter().map(|d| d.device_id.as_str()).collect();
        tracing::info!(
            device_idx = i,
            device_id = %device.device_id,
            all_device_ids = ?device_ids,
            snapshot = ?snapshot(device.root.path()),
            row_name,
            "final snapshot (name -> content hash)"
        );
    }

    // Taken once, before the comparison, so the failure message carries the
    // same three-field state the stall path reports -- the stable-but-wrong
    // convergence shape and the never-converges shape are distinguished by
    // exactly the same evidence.
    let probe = frontier_index_disk_probe(&devices, &group_id);
    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(
            snap, reference,
            "{probe}\n\
             {row_name}: device-{i} diverged from device-0 (device_count={device_count}, \
             stagger_ms={stagger_ms}) -- expect NAME-vs-CONTENT mismatch in a conflict copy \
             if the multiway conflict naming bug is present (a conflict-copy path embeds one \
             device's id but holds a DIFFERENT device's content, due to chained pairwise \
             resolution misattributing self.local_device_id/self.peer_device_id once `local` \
             no longer represents this device's own unmediated edit)"
        );
    }
}

// --- 4 device counts x 2 timings = 8 rows ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_simultaneous_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(3, 0, "multiway-3-sim", ConvergedShape::EveryWriterSurvives).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_staggered_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(3, 50, "multiway-3-stag", ConvergedShape::ReplicasAgree).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_devices_simultaneous_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(4, 0, "multiway-4-sim", ConvergedShape::EveryWriterSurvives).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_devices_staggered_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(4, 50, "multiway-4-stag", ConvergedShape::ReplicasAgree).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_devices_simultaneous_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(5, 0, "multiway-5-sim", ConvergedShape::EveryWriterSurvives).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_devices_staggered_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(5, 50, "multiway-5-stag", ConvergedShape::ReplicasAgree).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn six_devices_simultaneous_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(6, 0, "multiway-6-sim", ConvergedShape::EveryWriterSurvives).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn six_devices_staggered_write_never_mismatches_name_and_content() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    run_multiway_row(6, 50, "multiway-6-stag", ConvergedShape::ReplicasAgree).await;
}
