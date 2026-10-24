//! A third Taguchi-method (orthogonal-array) designed matrix of
//! concurrent-collision scenarios, run through the real daemon stack --
//! complementing `taguchi_collision_matrix.rs` (v1: device-count,
//! op-pattern, stagger, path-relationship, round-repetition) and
//! `taguchi_collision_matrix_v2.rs` (v2: file size, content pattern, path
//! depth, exec-bit toggling, device churn).
//!
//! v1 and v2 never combine network partition/reconnect timing
//! (`partition_reconnect_matrix.rs`'s domain) with device churn, rename/
//! directory topology (`directory_conflict_matrix.rs`'s domain), or
//! op-type combinations in a single matrix -- every historical silent
//! data-loss bug found by this test suite so far (a local edit silently
//! swallowed by its own self-echo, a multiway conflict-copy's name not
//! matching its content, and a local change lost to registration-mutex
//! contention) came from exactly this kind of previously-uncrossed timing
//! interaction. This file exists to close that gap: five *new* factors,
//! four levels each, covered pairwise-exhaustively by the same standard
//! L16(4^5) orthogonal array v1/v2 use (16 runs instead of 4^5 = 1024 for
//! a full factorial).
//!
//! Factors (see each `FACTOR_*` doc comment below for level definitions):
//! - A: partition/reconnect timing (none / full-offline-then-sync /
//!   partial-propagation-then-partition / flapping double-partition)
//! - B: op combination per device (all edit / edit-delete alternating /
//!   delete-vs-rename / rename-to-identical-new-name)
//! - C: path topology (flat single file / rename race onto a live path /
//!   nested directory with a directory-level rename / case-fold collision)
//! - D: device count + churn (2, no churn / 3, no churn / 4, a device
//!   joins mid-test / 4, a device is access-revoked mid-test)
//! - E: timing stagger (0/10/100/500ms between each device's own op),
//!   reusing v1's exact levels
//!
//! Device index 0 is a fixed always-online anchor in every row (never
//! paused), mirroring `partition_reconnect_matrix.rs`'s own two-device
//! shape generalized to N devices -- this guarantees a mid-partition
//! joiner/revokee (Factor D) always has at least one live peer to actually
//! race against, and matches this file's convergence assertions being
//! phrased "relative to device-0".
//!
//! Unlike v1's direct `connect_two_daemons` pairing, this file drives the
//! real `peer_orchestrator` against the in-process fake coordination plane
//! ([`support::fake_coordination`]): registering N devices in one group
//! makes the fake advertise a full mesh, and each device's orchestrator
//! connects to every co-group peer. This is what lets Factor D's churn
//! actually take effect -- an access revoke recomputes and pushes a netmap
//! without the revoked device, and the peers diff it and tear the session
//! down, exactly as the real plane would; a mid-test joiner is registered
//! with the fake and discovered by the existing devices. Partition is still
//! simulated locally via `set_paused`/`resume_link` (the sync layer's own
//! pause seam), independent of the coordination plane.
//!
//! `TestDevice`/`setup_device`/`n_synced_devices` are intentionally
//! duplicated from the other daemon integration test binaries rather than
//! shared -- matches this codebase's existing convention of self-contained
//! daemon integration test binaries.

mod support;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
use support::fake_coordination::FakeCoordination;
use support::{
    open_file_backed_replica_coordinator, real_entry_names, register_with_fake, wait_until,
    wait_until_with_context,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::MaterializationState;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // Uses file-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see
    // open_file_backed_replica_coordinator's doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
    _index_dir: tempfile::TempDir,
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

/// Stands up one real daemon wired into the fake coordination plane, in the
/// order the full-stack orchestrator path requires: build `DaemonState`,
/// `register_with_fake` (installs the change-signing key, binds the loopback
/// transport socket, advertises identity + group membership so the netmap
/// carries this device), start the link watch for every group, then spawn the
/// orchestrator against the fake. The fake pushes a fresh netmap on
/// registration, so co-group devices discover and connect to this one.
async fn setup_device(fake: &FakeCoordination, device_id: &str, groups: &[&str]) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    let root = tempfile::tempdir().unwrap();

    register_with_fake(fake, &state, device_id, groups).await;

    let local_path = root.path().to_string_lossy().to_string();
    for group_id in groups {
        state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
        LinkRuntimeController::new(state.clone())
            .start(local_path.clone(), group_id.to_string())
            .unwrap();
    }

    spawn_orchestrator(fake.addr(), device_id.to_string(), state.clone());

    TestDevice {
        device_id: device_id.to_string(),
        state,
        root,
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

/// Waits until every device in `devices` has an established peer session to
/// every other device in the set -- i.e. the fake-advertised full mesh has
/// actually formed over the real transport. Establishing the mesh *before*
/// any partition/churn action is what makes a mid-test revoke meaningful: the
/// revoked device is a live, connected peer whose session the netmap diff must
/// then tear down, not one that simply never connected.
async fn wait_for_mesh(devices: &[&TestDevice]) {
    wait_until(
        || {
            devices.iter().all(|d| {
                devices
                    .iter()
                    .filter(|o| o.device_id != d.device_id)
                    .all(|o| d.state.peers.session(&o.device_id).is_some())
            })
        },
        Duration::from_secs(30),
    )
    .await;
}

/// Sets up `n` devices sharing one group against the fake and waits for the
/// full mesh to form. Returns the devices; the caller keeps `fake` alive for
/// the churn action.
async fn n_synced_devices(
    fake: &FakeCoordination,
    n: usize,
    group_id: &str,
    device_prefix: &str,
) -> Vec<TestDevice> {
    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(fake, &format!("{device_prefix}-device-{i}"), &[group_id]).await);
    }
    // Before the mesh wait, not after: a `PeerSyncSession` only forms once
    // `SyncStack::link_to` resolves the peer's address from the
    // reconciliation substrate's own address directory -- the only plane
    // that carries DAG changes, a different socket with a different ALPN
    // from whatever the session itself connects over, and these fixtures
    // wire their own devices, so nobody learns where anybody's substrate
    // answers without this call. Waiting for sessions first is circular:
    // it waits on the exact connection this line is what makes possible.
    // See taguchi_collision_matrix_v2.rs's identical fix for the same bug.
    let states: Vec<&std::sync::Arc<DaemonState>> =
        devices.iter().map(|device| &device.state).collect();
    support::advertise_substrate_between(&states).await;
    let refs: Vec<&TestDevice> = devices.iter().collect();
    wait_for_mesh(&refs).await;
    wait_until(
        || {
            devices.iter().all(|device| {
                device
                    .state
                    .authority
                    .group_policy_state(group_id)
                    .is_some_and(|policy| policy.current_seq == 0)
                    && !device.state.authority.is_group_policy_stale(group_id)
            })
        },
        Duration::from_secs(30),
    )
    .await;
    devices
}

/// A recursive relative-path -> content-hash snapshot of everything under
/// `root`, duplicated from `directory_conflict_matrix.rs` -- needed here
/// (rather than the flat, top-level-only `real_entry_names`) because
/// Factor C level 3 nests its target file under a subdirectory.
fn recursive_snapshot(root: &Path) -> HashMap<String, String> {
    fn walk(base: &Path, current: &Path, out: &mut HashMap<String, String>) {
        let Ok(entries) = std::fs::read_dir(current) else { return };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            // The sync-root lock sits at the top of every linked root and is
            // excluded from sync, like the marker. The case-fold branch
            // counts non-conflict-copy entries, so leaving it in makes every
            // device report one canonical entry too many, forever. Both are
            // excluded only at the top of the root, as the product does
            // (`is_sync_root_lock_relative_path`,
            // `is_root_marker_relative_path`): a nested file with either
            // name is ordinary user content that syncs.
            let at_root_top = current == base;
            if (at_root_top
                && (name == yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME
                    || name == yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME))
                || name.contains(".yadorilink-tmp.")
                || yadorilink_fs_platform::reserved_namespace::is_reserved_component(
                    entry.file_name().as_os_str(),
                )
            {
                continue;
            }
            let Ok(file_type) = entry.file_type() else { continue };
            let path = entry.path();
            if file_type.is_dir() {
                walk(base, &path, out);
            } else if file_type.is_file() {
                let Ok(rel_path) = path.strip_prefix(base) else { continue };
                let rel_path = rel_path.to_string_lossy().replace('\\', "/");
                let content = std::fs::read(&path).unwrap_or_default();
                out.insert(rel_path, hex::encode(sha2::Sha256::digest(&content)));
            }
        }
    }
    let mut out = HashMap::new();
    walk(root, root, &mut out);
    out
}

/// One device's view of whether it still has sync work in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SyncWorkState {
    /// The device's DAG frontier, sorted.
    heads: Vec<String>,
    /// Every path the device holds that is not hydrated, sorted.
    unhydrated: Vec<String>,
    /// Projection obligations still pending.
    pending_obligations: u64,
}

fn sync_work_state(device: &TestDevice, group_id: &str) -> SyncWorkState {
    let coordinator = &device.state.replica_coordinator;
    let mut heads: Vec<String> = coordinator
        .sqlite()
        .native_group_heads(group_id)
        .unwrap()
        .iter()
        .map(|head| head.to_hex())
        .collect();
    heads.sort();
    let mut unhydrated: Vec<String> = coordinator
        .materialization_state_repository()
        .list_materialization_states(group_id)
        .unwrap()
        .into_iter()
        .filter(|(_, state)| *state != MaterializationState::Present)
        .map(|(path, _)| path)
        .collect();
    unhydrated.sort();
    let pending_obligations =
        coordinator.sqlite().dag_count_pending_projection_obligations(group_id).unwrap();
    SyncWorkState { heads, unhydrated, pending_obligations }
}

/// How long every device must hold one unchanged, shared frontier with no
/// outstanding work before the tree counts as settled. It only has to outlast
/// a hydration or projection that has not started yet.
const QUIESCENCE_WINDOW: Duration = Duration::from_secs(3);

/// Waits until the devices have stopped moving: every device reports the same
/// DAG frontier, nothing fetchable is left unhydrated or unprojected, that has
/// held unchanged for [`QUIESCENCE_WINDOW`].
///
/// Equal on-disk snapshots are not enough to call a row converged: a
/// not-yet-hydrated file is a placeholder of the right size and all zero
/// bytes, so devices that all still hold a placeholder at a path hash equal,
/// and each fills in its bytes at its own time afterwards. That let the
/// snapshot wait pass on an intermediate tree, and the final comparison then
/// caught devices part-way to the real end state.
///
/// `revoked_device` is true when a device was revoked mid-row. Content only
/// the revoked device ever held can no longer be fetched from anyone, so
/// every remaining device keeps that file as a placeholder, with its
/// projection obligation pending, for good (row 15). Those rows tolerate
/// a path left unhydrated only when no remaining device holds it hydrated,
/// so nobody left could serve it. Anything some remaining device does hold
/// must still hydrate everywhere, the same as in any other row.
///
/// `case_fold` is true for the case-fold rows. There a device holds back
/// whichever differently-cased sibling of the colliding name it did not index
/// first (a held entry is never materialized under any alternate name), so
/// that one path stays unhydrated, with at most one projection obligation
/// each, for good. Only those colliding names get this allowance; every other
/// path must hydrate and project as in any other row.
async fn wait_for_quiescence(
    devices: &[&TestDevice],
    group_id: &str,
    timeout: Duration,
    revoked_device: bool,
    case_fold: bool,
) {
    let colliding = target_path(4, 0).to_string_lossy().to_lowercase();
    let held = |path: &String| case_fold && path.to_lowercase() == colliding;
    let started = tokio::time::Instant::now();
    let mut stable: Option<(Vec<SyncWorkState>, tokio::time::Instant)> = None;
    loop {
        let states: Vec<SyncWorkState> =
            devices.iter().map(|d| sync_work_state(d, group_id)).collect();
        // The work that must drain: unhydrated paths other than held
        // case-fold names, and obligations beyond one per held name.
        let outstanding: Vec<(Vec<&String>, u64)> = states
            .iter()
            .map(|state| {
                let held_count = state.unhydrated.iter().filter(|p| held(p)).count() as u64;
                (
                    state.unhydrated.iter().filter(|p| !held(p)).collect(),
                    state.pending_obligations.saturating_sub(held_count),
                )
            })
            .collect();
        let reference_heads = &states[0].heads;
        let same_frontier = states.iter().all(|state| &state.heads == reference_heads);
        let nothing_fetchable_outstanding = if revoked_device {
            // A path unhydrated anywhere must be unhydrated everywhere: if
            // some remaining device holds it hydrated, the rest can still
            // fetch it and will change underneath the snapshot.
            outstanding.iter().all(|(unhydrated, _)| {
                unhydrated.iter().all(|path| {
                    outstanding.iter().all(|(other, _)| other.binary_search(path).is_ok())
                })
            })
        } else {
            outstanding.iter().all(|(unhydrated, pending)| unhydrated.is_empty() && *pending == 0)
        };
        if same_frontier && nothing_fetchable_outstanding {
            match &stable {
                Some((held, since)) if held == &states => {
                    if since.elapsed() >= QUIESCENCE_WINDOW {
                        return;
                    }
                }
                _ => stable = Some((states.clone(), tokio::time::Instant::now())),
            }
        } else {
            stable = None;
        }
        if started.elapsed() > timeout {
            let detail = devices
                .iter()
                .zip(states.iter())
                .map(|(d, state)| format!("{}: {state:?}", d.device_id))
                .collect::<Vec<_>>()
                .join("; ");
            let why = if !same_frontier {
                "frontiers never became equal"
            } else if !nothing_fetchable_outstanding {
                "frontiers equal but fetchable work (unhydrated/pending obligations) never drained"
            } else {
                "frontiers equal and work drained but the state kept changing"
            };
            panic!("devices never settled within {timeout:?} ({why}): {detail}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

fn pause(device: &TestDevice) {
    device
        .state
        .replica_coordinator
        .link_repository()
        .set_paused(device.root.path().to_str().unwrap(), true)
        .unwrap();
}

/// Resumes every device in `devices` -- per `partition_reconnect_matrix.
/// rs`'s own header doc comment, resuming a device that was never
/// actually paused is a harmless no-op as far as pause state goes, but it
/// forces that device to re-broadcast its current full index too, which
/// is what makes a still-online peer's changes (silently dropped on
/// arrival at a paused device during the offline window) visible once
/// everyone reconnects.
/// Resumes every device concurrently (`join_all`, not a sequential loop):
/// `peer_session::reconcile_files_if_authorized`'s "pause trumps
/// everything" rule silently drops an incoming update for a still-paused
/// link with no retry queued (confirmed investigating row 8's own
/// non-convergence) -- resuming devices one at a time left a real window
/// where an early-resumed device's full-index rebroadcast reaches a peer
/// that hasn't unpaused yet, losing that push with no fast-path recovery
/// (only the ~90s periodic full-index resync). Matches
/// `partition_reconnect_matrix.rs`'s own `partition_both_devices_paused_
/// simultaneously_resume_races_converges`, which already resumes its two
/// devices via `tokio::join!` for the identical reason.
///
/// `revoked` is the device whose access was revoked, if any. It has lost the
/// group's policy, so `resume` refuses it (its pending changes cannot be
/// captured); it is not part of the converged set either.
async fn resume_all(devices: &[TestDevice], revoked: Option<usize>) {
    let resumed: Vec<&TestDevice> = devices
        .iter()
        .enumerate()
        .filter(|(index, _)| Some(*index) != revoked)
        .map(|(_, device)| device)
        .collect();
    let controllers: Vec<_> =
        resumed.iter().map(|device| LinkRuntimeController::new(device.state.clone())).collect();
    let resumes = resumed
        .iter()
        .zip(controllers.iter())
        .map(|(device, controller)| resume_when_captured(controller, device));
    futures_util::future::join_all(resumes).await;
}

/// Resumes one device. A resume first captures the device's pending local changes, and refuses
/// (changing nothing) while one cannot be captured yet: a path being rewritten by a peer's
/// content arriving at the same moment is left for the next pass. That is a "retry" answer, and
/// a mid-row resume on a case-insensitive volume meets it, so it is retried here; any other
/// refusal is a failure.
async fn resume_when_captured(controller: &LinkRuntimeController, device: &TestDevice) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match controller.resume(device.root.path().to_str().unwrap()).await {
            Ok(()) => return,
            Err(error)
                if error.to_string().contains("could not be captured yet")
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => panic!("resume failed: {error}"),
        }
    }
}

// --- Factor B: op combination assigned per device index -------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Edit,
    Delete,
    Rename,
}

/// FACTOR B (op combination) -- always applied against Factor C's
/// `target_path`, with two exceptions handled at their call sites in
/// `apply_op`: path_level 2's rename-race override (device 0 always
/// renames regardless of its assigned op here), and op_level 4's
/// same-destination-for-everyone Rename semantics.
fn op_for_device(op_level: u8, device_idx: usize) -> Op {
    match op_level {
        1 => Op::Edit,
        2 => {
            if device_idx.is_multiple_of(2) {
                Op::Edit
            } else {
                Op::Delete
            }
        }
        3 => {
            if device_idx == 0 {
                Op::Delete
            } else {
                Op::Rename
            }
        }
        4 => Op::Rename,
        _ => unreachable!(),
    }
}

// --- Factor C: target path topology ---------------------------------------

/// FACTOR C (path topology) -- the relative path each device operates on.
/// Level 2's actual target is overridden for device 0 in `apply_op`
/// (device 0 always races the shared name's disappearance via rename);
/// level 4 gives even/odd device indices differently-cased names for the
/// same logical file, a genuine hazard only on a case-insensitive
/// filesystem (gated at the top of `run_taguchi_v3_row`, matching
/// `collision_matrix.rs`'s own case-fold scenario).
fn target_path(path_level: u8, device_idx: usize) -> PathBuf {
    match path_level {
        1 => PathBuf::from("shared.bin"),
        2 => PathBuf::from("shared.bin"),
        3 => PathBuf::from("shared_dir/target.bin"),
        4 => {
            if device_idx.is_multiple_of(2) {
                PathBuf::from("Shared.bin")
            } else {
                PathBuf::from("shared.bin")
            }
        }
        _ => unreachable!(),
    }
}

/// Applies `device_idx`'s Factor-B op at Factor-C's target path for this
/// round, with two path_level-specific overrides layered on top (see
/// `target_path`'s doc comment for the rename-race one; the directory
/// rename below is new).
fn apply_op(root: &Path, path_level: u8, op_level: u8, device_idx: usize, op: Op, round: u32) {
    let target = target_path(path_level, device_idx);
    let path = root.join(&target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    let content = format!("row round {round} device {device_idx} target {}", target.display());

    // path_level 2 (rename race): device 0 always races the shared
    // target's disappearance via rename, overriding whatever Factor B
    // assigned it, so every row selecting this path level actually
    // exercises "one device renames the shared target while everyone
    // else still touches the old name" regardless of the op-combination
    // factor.
    if path_level == 2 && device_idx == 0 {
        if path.exists() {
            let renamed = root.join(format!("shared-renamed-r{round}.bin"));
            support::rename_unless_vanished(&path, &renamed);
        } else {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        return;
    }

    match op {
        Op::Edit => {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        Op::Delete => {
            support::remove_file_unless_vanished(&path);
        }
        Op::Rename => {
            if path.exists() {
                let dest = if op_level == 4 {
                    // op_level 4: every device renames to the SAME new
                    // name -- a "multiple independent renames converging
                    // on one identical target" collision, distinct from
                    // `directory_conflict_matrix.rs`'s only-covered
                    // rename-to-*different*-targets shape.
                    root.join("renamed-shared.bin")
                } else {
                    root.join(format!(
                        "{}.renamed-{device_idx}-r{round}",
                        target.file_name().unwrap().to_string_lossy()
                    ))
                };
                support::rename_unless_vanished(&path, &dest);
            } else {
                std::fs::write(&path, content.as_bytes()).unwrap();
            }
        }
    }
}

/// path_level 3 (nested directory): on round 0 only, device 0 additionally renames the whole
/// shared parent directory right after its own op inside it -- combining
/// `directory_conflict_matrix.rs`'s "nested rename races a child edit" shape with this row's
/// partition/churn/op axes for the first time. The rename waits for the device's own capture to
/// be quiescent, so it races the peers' changes and not the daemon's own file opens.
async fn rename_shared_dir(device: &TestDevice, group_id: &str) {
    let dir = device.root.path().join("shared_dir");
    if !dir.exists() {
        return;
    }
    support::quiescence::wait_quiescent(device.root.path(), &device.state, group_id).await;
    support::rename_unless_vanished(&dir, &device.root.path().join("shared_dir-renamed"));
}

async fn apply_round_for_devices(
    devices: &[TestDevice],
    path_level: u8,
    op_level: u8,
    round: u32,
    stagger: Duration,
    group_id: &str,
) {
    for (idx, device) in devices.iter().enumerate() {
        let op = op_for_device(op_level, idx);
        apply_op(device.root.path(), path_level, op_level, idx, op, round);
        if path_level == 3 && idx == 0 && round == 0 {
            rename_shared_dir(device, group_id).await;
        }
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
    }
}

/// FACTOR E (timing stagger, in milliseconds between each device's own
/// operation being issued) -- identical levels to v1's own Factor C.
fn stagger_ms(level: u8) -> u64 {
    match level {
        1 => 0,
        2 => 10,
        3 => 100,
        4 => 500,
        _ => unreachable!(),
    }
}

/// Data-loss guard, independent of (and stronger than) the plain
/// convergence check in `run_taguchi_v3_row`: for every device whose
/// Factor-B-assigned *final* (round-1) op was a genuine content Edit
/// (Delete/Rename devices are skipped -- their survival shape is harder to
/// pin down deterministically given this row's path-level overrides, and
/// v1/v2/`directory_conflict_matrix.rs` already cover those shapes
/// elsewhere), that device's actual content must appear *somewhere* in the
/// final converged tree -- as the winning copy, a conflict copy, or any
/// other surviving name. Plain convergence alone does not guarantee this:
/// all devices could "converge" by silently ending up without content that
/// should exist, which is exactly the shape of the self-echo-race bug
/// this suite caught (a real edit `fs::remove_file`'d with no
/// conflict-copy artifact at all).
///
/// Skipped entirely for path_level 4 (case-fold): a case-insensitive
/// filesystem can only ever hold one of two differently-cased names, so
/// content can be legitimately un-representable as a separate on-disk
/// artifact there -- the same reasoning `collision_matrix.rs`'s own
/// case-fold scenario uses to stay convergence-only.
fn assert_no_content_silently_lost(
    devices: &[TestDevice],
    op_level: u8,
    path_level: u8,
    excluded_idx: Option<usize>,
    row_name: &str,
    final_snapshot: &HashMap<String, String>,
) {
    if let Some(lost) = lost_edit(devices, op_level, path_level, excluded_idx, final_snapshot) {
        panic!(
            "{row_name}: {lost} -- silent data loss (op_level={op_level}, path_level={path_level})"
        );
    }
}

/// The first Edit-device whose round-1 content is in none of `snapshot`'s hashes.
fn lost_edit(
    devices: &[TestDevice],
    op_level: u8,
    path_level: u8,
    excluded_idx: Option<usize>,
    snapshot: &HashMap<String, String>,
) -> Option<String> {
    if path_level == 4 {
        return None;
    }
    for idx in 0..devices.len() {
        if Some(idx) == excluded_idx {
            continue;
        }
        if op_for_device(op_level, idx) != Op::Edit {
            continue;
        }
        if path_level == 2 && idx == 0 {
            continue; // overridden to a rename, never a plain edit
        }
        let target = target_path(path_level, idx);
        let expected_content = format!("row round 1 device {idx} target {}", target.display());
        let expected_hash = hex::encode(sha2::Sha256::digest(expected_content.as_bytes()));
        if !snapshot.values().any(|h| h == &expected_hash) {
            return Some(format!(
                "device-{idx}'s round-1 edit (content hash {expected_hash}) is not present \
                 anywhere in the final tree"
            ));
        }
    }
    None
}

/// Every device's tree, entries named by device so none collides.
fn union_of_trees(devices: &[&TestDevice]) -> HashMap<String, String> {
    devices
        .iter()
        .enumerate()
        .flat_map(|(i, d)| {
            recursive_snapshot(d.root.path()).into_iter().map(move |(k, h)| (format!("{i}/{k}"), h))
        })
        .collect()
}

/// How many canonical (non-conflict-copy) entries a device may end with for the
/// case-fold collision.
///
/// op_level 4: every device renames what it sees onto `renamed-shared.bin` and
/// writes the colliding name again when it sees nothing there. Whether a later
/// device sees that rewrite before it acts (and so renames it too) depends on
/// how fast the devices converge, so the colliding name either survives as a
/// second canonical entry or is consumed by a rename. Both are correct, provided
/// nothing is lost: every version stays reachable as the canonical entry or a
/// conflict copy, and every device agrees on which (checked by the caller).
fn canonical_count_ok(op_level: u8, count: usize) -> bool {
    if op_level == 4 {
        count == 1 || count == 2
    } else {
        count == 1
    }
}

fn tree_dump(devices: &[&TestDevice]) -> String {
    devices
        .iter()
        .enumerate()
        .map(|(i, d)| format!("device-{i}={:?}", recursive_snapshot(d.root.path())))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Fails a case-fold row whose devices quiesced (equal frontiers, no outstanding
/// work) yet whose trees never held the agreed shape for a stable window: a
/// settled-but-different divergence, not a slow resync.
fn panic_settled_but_different(
    row_name: &str,
    devices: &[&TestDevice],
    group_id: &str,
    params: &str,
) -> ! {
    let trees = tree_dump(devices);
    let work = devices
        .iter()
        .map(|d| format!("{}: {:?}", d.device_id, sync_work_state(d, group_id)))
        .collect::<Vec<_>>()
        .join("; ");
    panic!(
        "{row_name}: devices quiesced (equal frontiers, no outstanding work) but the case-fold \
         tree check never held for a stable 5s window within 60s -- a settled-but-different \
         divergence, not a slow resync ({params}):\ntrees: {trees}\nsync work: {work}"
    );
}

/// Runs one Taguchi-array row: sets up devices per Factor D, applies
/// Factor D's churn action: returns the index of a revoked device, or a
/// freshly joined one.
async fn apply_churn(
    fake: &FakeCoordination,
    devices: &[TestDevice],
    churn_level: u8,
    row_name: &str,
    group_id: &str,
) -> (Option<usize>, Option<TestDevice>) {
    match churn_level {
        1 | 2 => (None, None),
        3 => {
            let new_device =
                setup_device(fake, &format!("{row_name}-device-churn-join"), &[group_id]).await;
            // The joiner arrives after `n_synced_devices` ran its
            // advertisement, so nobody knows where its reconciliation
            // substrate answers and it knows where nobody else's does.
            // Re-including the existing devices is idempotent.
            let mut states: Vec<&std::sync::Arc<DaemonState>> =
                devices.iter().map(|device| &device.state).collect();
            states.push(&new_device.state);
            support::advertise_substrate_between(&states).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            (None, Some(new_device))
        }
        4 => {
            let last = devices.len() - 1;
            fake.revoke(&devices[last].device_id, group_id);
            (Some(last), None)
        }
        _ => unreachable!(),
    }
}

/// With the Windows gate closed the trees cannot converge, so the only
/// property waited for is that no edit is lost.
async fn wait_for_no_lost_edit(
    row_name: &str,
    devices: &[TestDevice],
    active_refs: &[&TestDevice],
    op_level: u8,
    path_level: u8,
    excluded_idx: Option<usize>,
    timeout: Duration,
) {
    wait_until_with_context(
        || {
            lost_edit(devices, op_level, path_level, excluded_idx, &union_of_trees(active_refs))
                .is_none()
        },
        timeout,
        || {
            format!(
                "{row_name}: {:?}; {}",
                lost_edit(
                    devices,
                    op_level,
                    path_level,
                    excluded_idx,
                    &union_of_trees(active_refs)
                ),
                tree_dump(active_refs)
            )
        },
    )
    .await;
}

/// Factor A's partition/reconnect timing around two rounds of Factor-B/C-
/// driven operations (staggered per Factor E), applies Factor D's churn
/// action between the two rounds, waits for convergence, then asserts both
/// plain convergence and (except on path_level 4) the stronger
/// no-silent-data-loss property above.
#[allow(clippy::too_many_arguments)]
async fn run_taguchi_v3_row(
    row_name: &str,
    partition_level: u8,
    op_level: u8,
    path_level: u8,
    churn_level: u8,
    stagger_level: u8,
) {
    support::ensure_isolated_config_dir();
    let device_count: usize = match churn_level {
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 4,
        _ => unreachable!(),
    };
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "taguchi-v3-group";
    let devices = n_synced_devices(&fake, device_count, group_id, row_name).await;

    if path_level == 4
        && !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(devices[0].root.path())
    {
        eprintln!(
            "{row_name}: skipping case-fold path level -- {} is case-sensitive here",
            devices[0].root.path().display()
        );
        return;
    }

    let stagger = Duration::from_millis(stagger_ms(stagger_level));

    // Factor A: devices[1..] are the ones paused for partition levels 2-4;
    // device 0 is a fixed always-online anchor across every row (see this
    // file's header doc comment).
    let paused_indices: Vec<usize> = (1..device_count).collect();

    if matches!(partition_level, 2 | 4) {
        for &i in &paused_indices {
            pause(&devices[i]);
        }
    }
    apply_round_for_devices(&devices, path_level, op_level, 0, stagger, group_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    if partition_level == 3 {
        // Partial-propagation-then-partition: round 0 ran fully online
        // and was allowed to start propagating; only now do the
        // non-anchor devices go dark.
        for &i in &paused_indices {
            pause(&devices[i]);
        }
    }
    if partition_level == 4 {
        // Flapping: reconnect once before round 1, then partition again --
        // stresses whether a second offline window can silently drop
        // round-0's backlog before it finished flushing from the first
        // reconnect.
        resume_all(&devices, None).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        for &i in &paused_indices {
            pause(&devices[i]);
        }
    }

    // Factor D churn action, applied between the two rounds so it races
    // whatever partition state currently holds (online for level 1,
    // freshly offline for 2/3/4). The mesh is already fully connected (see
    // `n_synced_devices`), so a revoke here tears a live, established
    // session down rather than merely preventing a connection.
    let (excluded_idx, joined_device) =
        apply_churn(&fake, &devices, churn_level, row_name, group_id).await;

    apply_round_for_devices(&devices, path_level, op_level, 1, stagger, group_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    if matches!(partition_level, 2..=4) {
        resume_all(&devices, excluded_idx).await;
    }

    let active_refs: Vec<&TestDevice> = devices
        .iter()
        .enumerate()
        .filter(|(idx, _)| Some(*idx) != excluded_idx)
        .map(|(_, d)| d)
        .chain(joined_device.iter())
        .collect();

    // churn_level 3 (a device joining mid-test) is a genuinely slower
    // path, not a bug -- see `taguchi_collision_matrix_v2.rs`'s own
    // `wait_for_content_convergence` doc comment for the traced-through
    // reason (a joiner's eager reconcile can blow its own hydration
    // timeout under contention and fall back to the ~90s periodic
    // full-index resync). Give it matching headroom.
    let timeout =
        if churn_level == 3 { Duration::from_secs(200) } else { Duration::from_secs(150) };

    // The closed Windows gate withholds the winner's replacement of the loser's
    // original, so the trees cannot converge and the sync work stays pending by
    // design. What must hold meanwhile is that no edit is lost: its content is
    // still on the device that made it, or in a conflict copy, somewhere.
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "conflict convergence requires durable namespace replacement",
    ) {
        wait_for_no_lost_edit(
            row_name,
            &devices,
            &active_refs,
            op_level,
            path_level,
            excluded_idx,
            timeout,
        )
        .await;
        return;
    }

    // Every row, case-fold included, must reach true quiescence before any
    // tree comparison: equal frontiers, nothing fetchable left unhydrated or
    // unprojected, held for a stable window. A case-fold collision resolves
    // per-device (see below) but the sync work itself still has to drain.
    wait_for_quiescence(&active_refs, group_id, timeout, excluded_idx.is_some(), path_level == 4)
        .await;

    // path_level 4 (case-fold) is deliberately excluded from the strict
    // full-snapshot convergence check below: per `hazard.rs`'s "hold"
    // design and `collision_matrix.rs`'s own case-fold scenario
    // (`concurrent_differently_cased_create_is_a_hazard_on_case_
    // insensitive_filesystems`), a case-fold collision is resolved
    // per-device by whichever name that device happened to index first --
    // there is no guarantee, or intent, that every device converges on the
    // SAME canonical name. What must still hold: each device ends up with
    // exactly one canonical (non-conflict-copy) entry for the collision,
    // and any conflict-copy artifacts that do get created are identical
    // across devices (those go through the same conflict-copy machinery
    // as every other path level, which does converge).
    if path_level == 4 {
        // Case-insensitive-by-name conflict-copy comparison: a conflict
        // copy's filename is built from the original colliding name's own
        // case (`conflict.rs`'s copy-name builder), so two devices can
        // independently materialize the SAME conflict-copy content (same
        // UUID, same timestamp, same hash) under differently-cased
        // leading words -- the same per-device "whichever case I saw
        // first" hold semantics this whole branch already accounts for,
        // just showing up one level deeper on the copy name rather than
        // the original.
        fn conflict_copy_content(root: &Path) -> std::collections::BTreeSet<String> {
            recursive_snapshot(root)
                .into_iter()
                .filter(|(k, _)| is_conflict_copy(k))
                .map(|(_, content_hash)| content_hash)
                .collect()
        }
        // The hold latitude covers only the colliding name itself. Every
        // other canonical entry (op_level 4's `renamed-shared.bin`, the
        // one path all renames land on) does not collide, so it must hold
        // the same bytes under the same name on every device -- a device
        // count alone would pass two devices keeping different content
        // there.
        fn non_colliding_canonical(root: &Path) -> std::collections::BTreeMap<String, String> {
            let colliding = target_path(4, 0).to_string_lossy().to_lowercase();
            recursive_snapshot(root)
                .into_iter()
                .filter(|(k, _)| !is_conflict_copy(k) && k.to_lowercase() != colliding)
                .collect()
        }
        let converged = || {
            active_refs.iter().all(|d| {
                let snap = recursive_snapshot(d.root.path());
                canonical_count_ok(op_level, snap.keys().filter(|k| !is_conflict_copy(k)).count())
            }) && {
                let reference = conflict_copy_content(active_refs[0].root.path());
                active_refs[1..].iter().all(|d| conflict_copy_content(d.root.path()) == reference)
            } && {
                let reference = non_colliding_canonical(active_refs[0].root.path());
                active_refs[1..].iter().all(|d| non_colliding_canonical(d.root.path()) == reference)
            }
        };
        wait_until_with_context(converged, timeout, || tree_dump(&active_refs)).await;
        // The wait above can pass on a transiently equal state. Require the
        // whole check to keep holding for a stable window before the final
        // assertions, and fail loudly if that window never occurs: the devices
        // have quiesced (above), so a tree that keeps changing or never
        // agrees is a real divergence, not a slow resync.
        let settle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut stable_since = tokio::time::Instant::now();
        let mut settled = false;
        while tokio::time::Instant::now() < settle_deadline {
            if !converged() {
                stable_since = tokio::time::Instant::now();
            } else if stable_since.elapsed() >= Duration::from_secs(5) {
                settled = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if !settled {
            panic_settled_but_different(
                row_name,
                &active_refs,
                group_id,
                &format!(
                    "partition_level={partition_level}, op_level={op_level}, \
                     churn_level={churn_level}, stagger_level={stagger_level}"
                ),
            );
        }

        for (i, device) in active_refs.iter().enumerate() {
            let snap = recursive_snapshot(device.root.path());
            let canonical_count = snap.keys().filter(|k| !is_conflict_copy(k)).count();
            assert!(
                canonical_count_ok(op_level, canonical_count),
                "{row_name}: device-{i} has {canonical_count} canonical (non-conflict-copy) \
                 entries for the case-fold collision (partition_level={partition_level}, \
                 op_level={op_level}, churn_level={churn_level}, stagger_level={stagger_level}): {snap:?}"
            );
        }
        let reference_conflict_copies = conflict_copy_content(active_refs[0].root.path());
        for (i, device) in active_refs.iter().enumerate().skip(1) {
            let conflict_copies = conflict_copy_content(device.root.path());
            assert_eq!(
                conflict_copies, reference_conflict_copies,
                "{row_name}: device-{i}'s conflict-copy artifacts diverged from device-0's \
                 (partition_level={partition_level}, op_level={op_level}, churn_level={churn_level}, \
                 stagger_level={stagger_level})"
            );
        }
        let reference_non_colliding = non_colliding_canonical(active_refs[0].root.path());
        for (i, device) in active_refs.iter().enumerate().skip(1) {
            let non_colliding = non_colliding_canonical(device.root.path());
            assert_eq!(
                non_colliding, reference_non_colliding,
                "{row_name}: device-{i}'s non-colliding canonical entries diverged from \
                 device-0's (partition_level={partition_level}, op_level={op_level}, \
                 churn_level={churn_level}, stagger_level={stagger_level})"
            );
        }
    } else {
        wait_until_with_context(
            || {
                let reference = recursive_snapshot(active_refs[0].root.path());
                active_refs[1..].iter().all(|d| recursive_snapshot(d.root.path()) == reference)
            },
            timeout,
            || {
                active_refs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("device-{i}={:?}", recursive_snapshot(d.root.path())))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        )
        .await;

        // A final settle window, matching v1/v2's own reasoning: name/hash-set
        // convergence (checked above) doesn't guarantee every device has
        // finished materializing identical bytes down to the last one yet.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let reference = recursive_snapshot(devices[0].root.path());
        for (i, device) in active_refs.iter().enumerate().skip(1) {
            let snap = recursive_snapshot(device.root.path());
            assert_eq!(
                snap, reference,
                "{row_name}: device-{i} diverged from device-0 (partition_level={partition_level}, \
                 op_level={op_level}, path_level={path_level}, churn_level={churn_level}, \
                 stagger_level={stagger_level})"
            );
        }
    }

    let reference = recursive_snapshot(devices[0].root.path());
    assert_no_content_silently_lost(
        &devices,
        op_level,
        path_level,
        excluded_idx,
        row_name,
        &reference,
    );

    // Sanity check that the excluded (revoked) device, if any, did not
    // silently end up back in the converged set under a different name --
    // informational only (task context), since its future state is
    // explicitly out of scope once excluded.
    let _ = excluded_idx.map(|idx| real_entry_names(devices[idx].root.path()));
}

// --- L16(4^5) orthogonal array rows: (A partition, B op, C path, D churn, E stagger) ---
//
// The case-fold rows 04, 07, 10 and 13 skip on case-sensitive filesystems.
// With the Windows durability gate closed the winner does not replace the loser's original, so the
// full-tree convergence cannot complete; every row then checks only that no round-1 edit is lost
// (see `run_taguchi_v3_row`), and the convergence checks run again when the gate opens.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_01_part_none_op_all_edit_path_flat_churn_dc2_stag_sim() {
    run_taguchi_v3_row("taguchi-v3-01", 1, 1, 1, 1, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_02_part_none_op_edit_del_alt_path_rename_race_churn_dc3_stag_micro() {
    run_taguchi_v3_row("taguchi-v3-02", 1, 2, 2, 2, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_03_part_none_op_del_vs_rename_path_nested_dir_churn_dc4_join_stag_small() {
    run_taguchi_v3_row("taguchi-v3-03", 1, 3, 3, 3, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_04_part_none_op_rename_same_target_path_case_fold_churn_dc4_revoke_stag_large(
) {
    run_taguchi_v3_row("taguchi-v3-04", 1, 4, 4, 4, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_05_part_full_offline_op_all_edit_path_rename_race_churn_dc4_join_stag_large(
) {
    run_taguchi_v3_row("taguchi-v3-05", 2, 1, 2, 3, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_06_part_full_offline_op_edit_del_alt_path_flat_churn_dc4_revoke_stag_small()
{
    run_taguchi_v3_row("taguchi-v3-06", 2, 2, 1, 4, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_07_part_full_offline_op_del_vs_rename_path_case_fold_churn_dc2_stag_micro()
{
    run_taguchi_v3_row("taguchi-v3-07", 2, 3, 4, 1, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_08_part_full_offline_op_rename_same_target_path_nested_dir_churn_dc3_stag_sim(
) {
    run_taguchi_v3_row("taguchi-v3-08", 2, 4, 3, 2, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_09_part_partial_prop_op_all_edit_path_nested_dir_churn_dc4_revoke_stag_micro(
) {
    run_taguchi_v3_row("taguchi-v3-09", 3, 1, 3, 4, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_10_part_partial_prop_op_edit_del_alt_path_case_fold_churn_dc4_join_stag_sim(
) {
    run_taguchi_v3_row("taguchi-v3-10", 3, 2, 4, 3, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_11_part_partial_prop_op_del_vs_rename_path_flat_churn_dc3_stag_large() {
    run_taguchi_v3_row("taguchi-v3-11", 3, 3, 1, 2, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_12_part_partial_prop_op_rename_same_target_path_rename_race_churn_dc2_stag_small(
) {
    run_taguchi_v3_row("taguchi-v3-12", 3, 4, 2, 1, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_13_part_flap_op_all_edit_path_case_fold_churn_dc3_stag_small() {
    run_taguchi_v3_row("taguchi-v3-13", 4, 1, 4, 2, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_14_part_flap_op_edit_del_alt_path_nested_dir_churn_dc2_stag_large() {
    run_taguchi_v3_row("taguchi-v3-14", 4, 2, 3, 1, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_15_part_flap_op_del_vs_rename_path_rename_race_churn_dc4_revoke_stag_sim() {
    run_taguchi_v3_row("taguchi-v3-15", 4, 3, 2, 4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_16_part_flap_op_rename_same_target_path_flat_churn_dc4_join_stag_micro() {
    run_taguchi_v3_row("taguchi-v3-16", 4, 4, 1, 3, 2).await;
}
