//! Migrated from `yadorilink-peer-session`'s dead hazard-hold tests.
//!
//! Deleting the head-announcement Change protocol removed the
//! only wire mechanism `PeerSyncSession` ever had for telling a connected
//! peer about a new/changed DAG record. Five tests in
//! `yadorilink-peer-session/tests/peer_session.rs` built two bare
//! `PeerSyncSession::standalone()` instances and expected a change authored
//! on one to reach the other via that now-deleted mechanism -- dead on Linux
//! (an early `is_case_insensitive_filesystem` guard fired first and the
//! body, including the now-impossible propagation, never ran) and hanging
//! for real on macOS (the guard doesn't fire there, so the body ran and
//! waited forever). The real replacement for DAG propagation is this
//! daemon's `PeerSessionDriver` (RBSR/substrate-based), which lives
//! entirely outside `yadorilink-peer-session` -- so all five are migrated
//! here, driven through the real full daemon stack (`connect_two_daemons`,
//! real transport, real peer sessions) `collision_matrix.rs` already uses
//! for its own collision scenarios, rather than patched in place.
//!
//! The underlying hazard/collision machinery (`hazard.rs`,
//! `local_convergence.rs`) is unchanged and confirmed correct; only the
//! propagation these tests drive it through moves from a dead bare-session
//! pair to real `two_synced_devices` reconciliation. Kept in its own file
//! rather than folded into `collision_matrix.rs`: these five spin up a full
//! coordination server + two-daemon mesh each, same as every scenario in
//! that file, and appending them there was observed to push
//! `collision_matrix.rs`'s own `concurrent_edit_edit_keeps_both_copies_as_
//! original_plus_conflict_copy` (which depends on a tight ~30ms wall-clock
//! margin between two edits) past its margin under `--test-threads=4`
//! parallel load from the added tests sharing the same test binary -- a
//! real, reproduced side effect, not a hypothetical one. A separate `.rs`
//! file is a separate test binary, so it carries none of that shared
//! thread-pool contention.
//!
//! `TestDevice`/`setup_device`/`start_watching`/`two_synced_devices` are
//! intentionally duplicated from `collision_matrix.rs` rather than shared --
//! matches this codebase's existing convention of self-contained daemon
//! integration test binaries (see that file's own doc comment).

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{real_entry_names, wait_until, wait_until_with_context, TestAccount};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;

use yadorilink_daemon::sync_error::SyncError;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{
    BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
};
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_root_authority::root_commit::RootCommitPermit;

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

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
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
    let group_id = support::create_folder_group(&account, "hazard-collision-group").await;
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

/// Every path `device`'s index currently carries for `group_id`, with its
/// deleted flag.
///
/// The on-disk entry list cannot distinguish "this device never received
/// the record" from "it received the record and correctly refused to write
/// it": a hold is precisely the case where the index knows about a path
/// that disk does not have. So a hold-related failure has to report the
/// index, not just the directory.
fn index_paths(device: &TestDevice, group_id: &str) -> Vec<(String, bool)> {
    match device.state.replica_coordinator.file_index_repository().list_files(group_id) {
        Ok(files) => files.into_iter().map(|f| (f.path, f.deleted)).collect(),
        Err(error) => vec![(format!("index_error={error}"), false)],
    }
}

fn index_summary(device: &TestDevice, group_id: &str, path: &str) -> String {
    match (
        device
            .state
            .replica_coordinator
            .file_index_repository()
            .get_file(group_id, path)
            .map_err(SyncError::from),
        device
            .state
            .replica_coordinator
            .sqlite()
            .dag_list_versions(group_id, path)
            .map_err(SyncError::from),
    ) {
        (Ok(current), Ok(versions)) => format!("current={current:?} versions={versions:?}"),
        (Err(error), _) | (_, Err(error)) => format!("versions_error={error}"),
    }
}

/// Authors a real, signed DAG `Create` Change for `path` in `group_id` on
/// `device`, storing `content`'s bytes in `device`'s own block store and
/// recording group block provenance for them -- WITHOUT writing anything
/// to `device`'s own local filesystem. Mirrors `stage2_block_serve_
/// contract.rs`'s own `seed_block` (a real signed, provenance-backed
/// Change is required for the content to be servable at all -- proof-
/// carrying-change admission rejects a raw `upsert_file` with no
/// authoring Change behind it).
///
/// Used for the SECOND half of every case-fold/normalization collision
/// pair below instead of a second real `std::fs::write`: on a case-
/// insensitive volume that already holds "Photo.jpg", writing "photo.jpg"
/// would not create a second file at all -- the OS's own case folding
/// would silently overwrite the first one under a different spelling,
/// which is exactly the ambiguity these scenarios exist to prove the sync
/// engine itself never manufactures. A pure DAG-level Create sidesteps
/// that physical constraint entirely (nothing is ever written to the
/// authoring device's own disk for it), matching what the original,
/// now-deleted `peer_session.rs` tests already did for the identical
/// reason (`DagProducer::commit_create`).
/// A modification time the projection can write back to disk: a zero mtime is
/// "unset", and the row would then show the time it was written, a different
/// version from the head the fixture authored.
const FIXTURE_MTIME: i64 = 1_700_000_000_000_000_000;

fn commit_pure_dag_create(device: &TestDevice, group_id: &str, path: &str, content: &[u8]) {
    let hash_hex = device.state.block_store.put(content).unwrap();
    let hash = hex::decode(&hash_hex).unwrap();
    let version_blocks =
        vec![VersionBlock { hash: BlockHash(hash.clone()), size: content.len() as u32 }];
    let version = FileVersion::new(
        version_blocks,
        content.len() as u64,
        FileMeta {
            mtime_unix_nanos: FIXTURE_MTIME,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let record = FileRecord {
        path: path.to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: FIXTURE_MTIME,
        blocks: vec![BlockInfo { hash: hash.clone(), offset: 0, size: content.len() as u32 }],
        deleted: false,
    };
    let signing_key =
        device.state.device_signing_key().expect("setup_device calls ensure_device_signing_key");
    let emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
        &device.state.replica_coordinator,
        &device.device_id,
        signing_key,
    )
    .unwrap();
    yadorilink_daemon::test_support::local_seam::commit_local_upsert(
        &device.state.replica_coordinator,
        group_id,
        &record,
        &device.device_id,
        &version,
        None,
        &emitter,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    device
        .state
        .replica_coordinator
        .record_block_provenance(group_id, std::slice::from_ref(&hash))
        .unwrap();
}

/// Authors a real, signed DAG `Delete` (tombstone) Change for `path` in
/// `group_id` on `device`, again without touching `device`'s own local
/// filesystem -- see `commit_pure_dag_create`'s doc comment for why a real
/// local delete on the authoring device is not always possible for these
/// scenarios (a device that had genuinely materialized the LIVE name for
/// real could never also hold the colliding name on the same disk to
/// delete it from). A third device that knows about a path only through
/// the DAG (e.g. a peer that never hydrated it) legitimately deletes it
/// this same way in production. Returns the tombstone's own `DeltaHash`
/// so a caller can confirm it was actually admitted on the receiving
/// device (`ChangeHistoryRepository::dag_has_change`) rather than
/// trusting timing alone -- the "hold in place" branch this tombstone is
/// meant to exercise (`local_convergence.rs::materialize_tombstone`)
/// deliberately leaves an already-held row's own state completely
/// unchanged, so held-state alone cannot distinguish "the tombstone
/// arrived and was correctly held" from "the tombstone never arrived at
/// all".
/// Authors a real, signed DAG `Delete` for `path` on `device`.
///
/// Removes the authoring device's own on-disk copy first, in that order,
/// exactly as the production delete path does. Recording the tombstone while
/// the file is still on disk leaves that device's index saying `deleted =
/// true` about a file that is still there, which its own scan then correctly
/// resurrects and re-propagates as a brand-new local edit -- a Put that
/// supersedes this tombstone on every replica. That is real, intended
/// product behaviour (`materialize`'s own "remove first, then record"
/// comment describes the same ordering requirement), so a test that skips
/// the removal is not testing a tombstone at all; it is racing the authoring
/// device's watcher for the meaning of its own change.
fn commit_pure_dag_tombstone(device: &TestDevice, group_id: &str, path: &str) {
    let on_disk = device.root.path().join(path);
    match std::fs::remove_file(&on_disk) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("could not remove {}: {e}", on_disk.display()),
    }
    let signing_key =
        device.state.device_signing_key().expect("setup_device calls ensure_device_signing_key");
    let emitter = yadorilink_daemon::test_support::local_seam::replica_author_key(
        &device.state.replica_coordinator,
        &device.device_id,
        signing_key,
    )
    .unwrap();
    yadorilink_daemon::test_support::local_seam::commit_local_delete(
        &device.state.replica_coordinator,
        group_id,
        path,
        &device.device_id,
        0,
        false,
        &emitter,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
}

/// Whether `device` has admitted the removal of `path`: no live native head
/// is left there.
fn native_head_gone(device: &TestDevice, group_id: &str, path: &str) -> bool {
    device
        .state
        .replica_coordinator
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &FolderGroupId(group_id.to_owned()),
                &yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
            )
        })
        .unwrap()
        .is_empty()
}

/// Publishes `device`'s pending content for `group_id` and wakes its
/// `PeerSessionDriver` -- the two effects `DaemonState::note_local_
/// commit_for_group` raises for every ordinary local mutation
/// (`on_local_native_commit`'s own chokepoint), reproduced explicitly here
/// because `commit_pure_dag_create`/`commit_pure_dag_tombstone` author
/// directly against `ReplicaCoordinator`, bypassing that chokepoint (and
/// its private, crate-internal notification) on purpose -- see their own
/// doc comments for why a real local mutation isn't available for these
/// records. Without this, the authored Change would sit `Pending` (or
/// `Published` but never announced) until the driver's own, much slower
/// periodic sweep happened to notice it.
async fn publish_and_wake(device: &TestDevice, group_id: &str) {
    device.state.flush_pending_checkpoint_for_group_for_test(group_id).await;
    device.state.flush_pending_native_checkpoint_for_group_for_test(group_id).await;
}

/// Like `two_synced_devices`, but device B links its folder with
/// `MaterializationPolicy::OnDemand` instead of the implicit default every
/// other scenario in this file uses. Needed only by `hydrate_file_reports_
/// held_not_hydrated_when_a_hazard_collision_exists`, whose whole point is
/// a SEPARATE, deliberately-triggered on-access hydrate call rather than
/// the ordinary eager-materialize path.
async fn synced_devices_with_b_on_demand(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "hazard-collision-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    start_watching(&device_a, &group_id).await;

    let root_b = device_b.root.path().to_string_lossy().to_string();
    device_b.state.set_test_on_demand_allowed(true);
    device_b.state.replica_coordinator.link_repository().add_link(&root_b, &group_id).unwrap();
    device_b
        .state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(&root_b, MaterializationPolicy::OnDemand)
        .unwrap();
    LinkRuntimeController::new(device_b.state.clone()).start(root_b, group_id.clone()).unwrap();

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

/// Migrated from the deleted `peer_session.rs::case_fold_collision_holds_
/// the_second_arriving_file_without_touching_the_first` (see this file's
/// header comment for why). Device A's "Photo.jpg" fully materializes on
/// device B first, via a real local edit and real reconciliation; only
/// afterward does a second, real-content record for "photo.jpg" (differing
/// only in case) arrive. The second-arriving record must be held -- never
/// written to disk under its own name or any other -- while the first,
/// already-materialized file is left completely untouched. Complements
/// `collision_matrix.rs`'s own `concurrent_differently_cased_create_is_a_
/// hazard_on_case_insensitive_filesystems` (both creates racing) by pinning
/// down the SEQUENTIAL, unambiguous-winner case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case_fold_collision_holds_the_second_arriving_file_without_touching_the_first() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-case-fold-sequential").await;

    // A real local edit and real reconciliation -- this part is not
    // filesystem-case-dependent at all, so it runs for real on every
    // platform, Linux included.
    std::fs::write(device_a.root.path().join("Photo.jpg"), b"original photo bytes").unwrap();
    let first_replicated = device_b.root.path().join("Photo.jpg");
    wait_until(|| first_replicated.exists(), Duration::from_secs(10)).await;
    assert_eq!(std::fs::read(&first_replicated).unwrap(), b"original photo bytes");

    // Only the actual collision below is meaningless on a case-sensitive
    // filesystem (see `hazard_reason_for_policy`) -- skip just that part
    // here, rather than gating this whole test on one guard.
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(device_b.root.path()) {
        eprintln!(
            "skipping the collision-specific assertions: {} is case-sensitive here",
            device_b.root.path().display()
        );
        return;
    }

    let second_bytes = b"a completely different photo";
    commit_pure_dag_create(&device_a, &group_id, "photo.jpg", second_bytes);
    publish_and_wake(&device_a, &group_id).await;

    wait_until_with_context(
        || {
            device_b
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(&group_id, "photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
        || {
            // Both roots and both index views: "the record never reached
            // device-b at all" and "it reached device-b but was not held"
            // are different bugs, and the on-disk entry list alone cannot
            // tell them apart -- a device that never received the record
            // and one that received it and correctly refused to write it
            // both show only the first file on disk.
            format!(
                "device-a root={} index={:?}; device-b root={} entries={:?} index={:?}",
                device_a.root.path().display(),
                index_paths(&device_a, &group_id),
                device_b.root.path().display(),
                real_entry_names(device_b.root.path()),
                index_paths(&device_b, &group_id),
            ) + &format!(
                " device-b disk_bytes={:?}",
                real_entry_names(device_b.root.path())
                    .iter()
                    .map(|name| (
                        name.clone(),
                        std::fs::read(device_b.root.path().join(name))
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_else(|e| format!("read_error={e}"))
                    ))
                    .collect::<Vec<_>>()
            )
        },
    )
    .await;

    let held = device_b
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_held_state(&group_id, "photo.jpg")
        .unwrap()
        .unwrap();
    assert!(held.reason.starts_with("case_collision"), "unexpected reason: {}", held.reason);

    // A held record still keeps its own index row.
    let stored = device_b
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, "photo.jpg")
        .unwrap()
        .unwrap();
    assert!(!stored.deleted);
    assert_eq!(stored.size, second_bytes.len() as u64);

    // The actual regression assertion: device B's sync root must contain
    // *exactly* the one, original, non-hazardous file. No `photo.jpg`, no
    // numbered/suffixed variant of either name (`Photo (1).jpg`,
    // `photo_2.jpg`, ...) -- nothing beyond what a completely ordinary,
    // uncontested sync would have produced.
    assert_eq!(
        real_entry_names(device_b.root.path()),
        vec!["Photo.jpg".to_string()],
        "a name hazard must never produce a written file under any name other than the \
         original — this crate implements no automatic rename/escape path"
    );
    assert_eq!(
        std::fs::read(&first_replicated).unwrap(),
        b"original photo bytes",
        "the first, already-materialized file must be completely untouched by the second \
         record's collision"
    );
}

/// Migrated from the deleted `peer_session.rs::combined_case_and_
/// normalization_collision_holds_the_second_arriving_file`. A pair
/// differing in BOTH case AND Unicode normalization form at once
/// (`"Café.txt"`, composed é, vs `"café.txt"`, decomposed é) escapes
/// `case_fold_collision` and `normalization_collision` independently (each
/// checks only one axis), but collides to one physical file on a volume
/// that is simultaneously case-insensitive AND normalization-insensitive
/// -- the macOS default (both HFS+ and APFS). See `hazard::case_and_
/// normalization_collision`'s doc comment for the reasoning; this is the
/// same scenario as the test above, through the real reconciliation path,
/// for the combined axis.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn combined_case_and_normalization_collision_holds_the_second_arriving_file() {
    let (device_a, device_b, group_id) =
        two_synced_devices("collision-case-and-normalization").await;

    // A real local edit and real reconciliation, unconditional on
    // platform -- see the sequential single-axis test above.
    let first_path = device_a.root.path().join("Caf\u{e9}.txt");
    std::fs::write(&first_path, b"original cafe bytes").unwrap();
    let first_replicated = device_b.root.path().join("Caf\u{e9}.txt");
    wait_until(|| first_replicated.exists(), Duration::from_secs(10)).await;
    assert_eq!(std::fs::read(&first_replicated).unwrap(), b"original cafe bytes");

    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(device_b.root.path())
        || !yadorilink_peer_session::hazard::is_normalization_insensitive_filesystem(
            device_b.root.path(),
        )
    {
        eprintln!(
            "skipping the collision-specific assertions: {} is not both case- and \
             normalization-insensitive here",
            device_b.root.path().display()
        );
        return;
    }

    // "cafe\u{301}.txt" -- lowercase c, DECOMPOSED é. Differs from the
    // first in both case and normalization form at once.
    let second_path = "cafe\u{301}.txt";
    let second_bytes = b"a completely different cafe";
    commit_pure_dag_create(&device_a, &group_id, second_path, second_bytes);
    publish_and_wake(&device_a, &group_id).await;

    wait_until_with_context(
        || {
            device_b
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(&group_id, second_path)
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
        || {
            // Both roots and both index views: "the record never reached
            // device-b at all" and "it reached device-b but was not held"
            // are different bugs, and the on-disk entry list alone cannot
            // tell them apart -- a device that never received the record
            // and one that received it and correctly refused to write it
            // both show only the first file on disk.
            format!(
                "device-a root={} index={:?}; device-b root={} entries={:?} index={:?}",
                device_a.root.path().display(),
                index_paths(&device_a, &group_id),
                device_b.root.path().display(),
                real_entry_names(device_b.root.path()),
                index_paths(&device_b, &group_id),
            ) + &format!(
                " device-b disk_bytes={:?}",
                real_entry_names(device_b.root.path())
                    .iter()
                    .map(|name| (
                        name.clone(),
                        std::fs::read(device_b.root.path().join(name))
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_else(|e| format!("read_error={e}"))
                    ))
                    .collect::<Vec<_>>()
            )
        },
    )
    .await;

    let held = device_b
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_held_state(&group_id, second_path)
        .unwrap()
        .unwrap();
    assert!(
        held.reason.starts_with("case_and_normalization_collision"),
        "unexpected reason: {}",
        held.reason
    );

    assert_eq!(
        real_entry_names(device_b.root.path()),
        vec!["Caf\u{e9}.txt".to_string()],
        "a combined-axis hazard must never produce a written file under any name other than the \
         original"
    );
    assert_eq!(
        std::fs::read(&first_replicated).unwrap(),
        b"original cafe bytes",
        "the first, already-materialized file must be completely untouched by the second \
         record's collision"
    );
}

/// Migrated from the deleted `peer_session.rs::hydrate_file_reports_held_
/// not_hydrated_when_a_hazard_collision_exists`. Unlike the other four
/// tests in this file, this one is NOT purely about `PeerSessionDriver`
/// propagation: `PeerSyncSession::hydrate_file` is on-access, per-session
/// hydration -- transport/RPC-level behavior belonging to the peer session,
/// not the DAG-propagation authority (see this file's header comment for
/// that split). What genuinely needed migrating here is the SAME thing as
/// the other four: the propagation of the colliding record onto device B
/// must go through real reconciliation, not a dead bare-session pair.
///
/// Honest limitation surfaced by this migration, not papered over: the
/// daemon's OWN newer, multi-peer on-demand hydration orchestrator
/// (`yadorilink_daemon::hydration::hydrate`, wired to the shell-IPC
/// `HydrateRequest` handler in production) does not consult the hazard/
/// held machinery at all before its physical write -- confirmed by
/// inspection (no reference to `hazard`/`held`/`case_collision` anywhere in
/// `hydration.rs`). That is a real, separate gap in the CURRENT production
/// on-demand-hydrate path, outside this migration's scope to fix. What
/// remains correct and testable today is `PeerSyncSession::hydrate_file`'s
/// own hazard re-check -- still live production code, just not the
/// daemon's current on-demand-hydrate entry point -- exercised here via the
/// REAL `PeerSyncSession` this real daemon topology already established
/// for this pairing (`DaemonState::peers::session`), never a bare,
/// disconnected `PeerSyncSession::standalone()`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hydrate_file_reports_held_not_hydrated_when_a_hazard_collision_exists() {
    let (device_a, device_b, group_id) =
        synced_devices_with_b_on_demand("collision-hydrate-held-hazard").await;
    device_b.state.set_test_on_demand_allowed(true);

    // A genuine sibling already on device_b -- present before the
    // incoming placeholder even arrives, via a real local write device_b's
    // own watcher captures normally. Not itself filesystem-case-dependent,
    // so it runs for real on every platform, Linux included.
    std::fs::write(device_b.root.path().join("Photo.jpg"), b"sibling bytes").unwrap();
    wait_until(
        || {
            device_b
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(&group_id, "Photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(10),
    )
    .await;

    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(device_b.root.path()) {
        eprintln!(
            "skipping the collision-specific assertions: {} is case-sensitive here -- the \
             on-demand pairing and adoption above already ran for real on every platform",
            device_b.root.path().display()
        );
        return;
    }

    // The incoming "photo.jpg" record -- see `commit_pure_dag_create`'s
    // doc comment for why this is authored purely at the DAG level rather
    // than as a real write on device A.
    let content = vec![0x55u8; 50_000];
    commit_pure_dag_create(&device_a, &group_id, "photo.jpg", &content);
    publish_and_wake(&device_a, &group_id).await;

    // The incoming record lands in the index (held, via the same
    // create-hazard-hold path the previous two tests exercise), but
    // `hydrate_file` is a SEPARATE, on-access path this test drives
    // directly regardless of how the index row got there.
    wait_until_with_context(
        || {
            device_b
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(&group_id, "photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
        || {
            // Both roots and both index views: "the record never reached
            // device-b at all" and "it reached device-b but was not held"
            // are different bugs, and the on-disk entry list alone cannot
            // tell them apart -- a device that never received the record
            // and one that received it and correctly refused to write it
            // both show only the first file on disk.
            format!(
                "device-a root={} index={:?}; device-b root={} entries={:?} index={:?}",
                device_a.root.path().display(),
                index_paths(&device_a, &group_id),
                device_b.root.path().display(),
                real_entry_names(device_b.root.path()),
                index_paths(&device_b, &group_id),
            ) + &format!(
                " device-b disk_bytes={:?}",
                real_entry_names(device_b.root.path())
                    .iter()
                    .map(|name| (
                        name.clone(),
                        std::fs::read(device_b.root.path().join(name))
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_else(|e| format!("read_error={e}"))
                    ))
                    .collect::<Vec<_>>()
            )
        },
    )
    .await;

    // The production in-place hydration: a path held for a hazard collision is never written under the
    // colliding name, whatever the fetch did, and stays held with its reason.
    let outcome =
        yadorilink_daemon::hydration::hydrate(&device_b.state, &group_id, "photo.jpg").await;
    let held = device_b
        .state
        .replica_coordinator
        .get_held_state(&group_id, "photo.jpg")
        .unwrap()
        .unwrap_or_else(|| {
            panic!("a hazard-collision hydration must leave the path held: {outcome:?}")
        });
    let reason = held.reason;
    assert!(reason.starts_with("case_collision"), "unexpected reason: {reason}");
    assert!(
        !device_b.root.path().join("photo.jpg").exists()
            || std::fs::read(device_b.root.path().join("photo.jpg")).unwrap() == b"sibling bytes",
        "the incoming content must never land on disk under this colliding name"
    );
    assert_eq!(
        std::fs::read(device_b.root.path().join("Photo.jpg")).unwrap(),
        b"sibling bytes",
        "the sibling must remain untouched"
    );
}

/// Migrated from the deleted `peer_session.rs::tombstone_of_a_case_fold_
/// colliding_path_holds_rather_than_deletes_the_sibling`. A TOMBSTONE for a
/// case-fold-colliding path must be held, exactly like a non-delete record
/// with the same collision -- not dispatched straight to `remove_file`,
/// which on a case-insensitive filesystem physically deletes whatever
/// sibling the index/disk actually has. "Photo.jpg" materializes first (a
/// real local edit, real reconciliation); "photo.jpg" (different case)
/// then arrives and is held (same mechanism the tests above prove);
/// finally a tombstone for that SAME held "photo.jpg" arrives. The correct
/// outcome: the tombstone is held too, and "Photo.jpg" is left completely
/// untouched on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tombstone_of_a_case_fold_colliding_path_holds_rather_than_deletes_the_sibling() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-tombstone-sibling").await;

    // "Photo.jpg" already materialized on device_b -- a real local edit on
    // A, propagated by real reconciliation, exactly as an ordinary prior
    // sync would leave it. Not itself filesystem-case-dependent, so it
    // runs for real on every platform, Linux included.
    std::fs::write(device_a.root.path().join("Photo.jpg"), b"original photo bytes").unwrap();
    let first_path = device_b.root.path().join("Photo.jpg");
    wait_until(|| first_path.exists(), Duration::from_secs(10)).await;

    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(device_b.root.path()) {
        eprintln!(
            "skipping the collision-specific assertions: {} is case-sensitive here",
            device_b.root.path().display()
        );
        return;
    }

    // device_b already tracks "photo.jpg" itself, held from an earlier
    // create-collision -- `materialize` only ever dispatches a record to
    // the hazard check being tested here when the local index already has
    // SOME entry for that exact path, so this precondition (not a
    // synthetic index row seeded out of nowhere) is what makes the
    // tombstone below reach the branch under test.
    commit_pure_dag_create(&device_a, &group_id, "photo.jpg", b"a completely different photo");
    publish_and_wake(&device_a, &group_id).await;
    wait_until_with_context(
        || {
            device_b
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(&group_id, "photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
        || {
            // Both roots and both index views: "the record never reached
            // device-b at all" and "it reached device-b but was not held"
            // are different bugs, and the on-disk entry list alone cannot
            // tell them apart -- a device that never received the record
            // and one that received it and correctly refused to write it
            // both show only the first file on disk.
            format!(
                "device-a root={} index={:?}; device-b root={} entries={:?} index={:?}",
                device_a.root.path().display(),
                index_paths(&device_a, &group_id),
                device_b.root.path().display(),
                real_entry_names(device_b.root.path()),
                index_paths(&device_b, &group_id),
            ) + &format!(
                " device-b disk_bytes={:?}",
                real_entry_names(device_b.root.path())
                    .iter()
                    .map(|name| (
                        name.clone(),
                        std::fs::read(device_b.root.path().join(name))
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_else(|e| format!("read_error={e}"))
                    ))
                    .collect::<Vec<_>>()
            )
        },
    )
    .await;

    // device_a commits a tombstone for the colliding-but-not-identical
    // "photo.jpg" into the change DAG; device_b adopts it via real
    // reconciliation. `dag_has_change` (not the held state, which a
    // redundant hold-in-place leaves completely untouched -- see
    // `commit_pure_dag_tombstone`'s own doc comment) is what actually
    // proves the tombstone was admitted, rather than trusting timing.
    commit_pure_dag_tombstone(&device_a, &group_id, "photo.jpg");
    publish_and_wake(&device_a, &group_id).await;
    wait_until_with_context(
        || native_head_gone(&device_b, &group_id, "photo.jpg"),
        Duration::from_secs(20),
        || "device-b never admitted the removal".to_string(),
    )
    .await;

    let held = device_b
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_held_state(&group_id, "photo.jpg")
        .unwrap()
        .unwrap();
    assert!(held.reason.starts_with("case_collision"), "unexpected reason: {}", held.reason);

    assert_eq!(
        std::fs::read(&first_path).unwrap(),
        b"original photo bytes",
        "a colliding tombstone must never physically delete the sibling it collides with"
    );
}

/// Migrated from the deleted `peer_session.rs::tombstone_of_the_live_file_
/// itself_does_not_corrupt_its_own_index_row_when_held`. A hazardous
/// tombstone targeting the path that is ITSELF the live, materialized file
/// must not corrupt that path's own index row. Unlike the sibling-targeted
/// scenario above (where the tombstoned path has no file on disk to begin
/// with), holding a tombstone for "Photo.jpg" -- which really is live on
/// disk -- must not adopt the incoming record's `deleted=true` over
/// "Photo.jpg"'s own row: that would leave the index saying "Photo.jpg" is
/// deleted while the file is still physically present, exactly the
/// divergence a later local scan reads as a brand-new local edit and
/// resurrects/re-propagates.
///
/// The colliding sibling and the tombstone are both authored as pure DAG
/// changes on device A -- see `commit_pure_dag_create`'s doc comment: a
/// device that had genuinely, locally materialized "Photo.jpg" for real
/// could never also hold a real "photo.jpg" on the SAME case-insensitive
/// disk to delete it from. A third device that knows "Photo.jpg" only
/// through the DAG (e.g. a peer that never hydrated it) legitimately
/// deletes it this same way in production.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tombstone_of_the_live_file_itself_does_not_corrupt_its_own_index_row_when_held() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-tombstone-live-file").await;

    // "Photo.jpg" is the live, materialized file -- a real local edit on
    // device_b itself. Not itself filesystem-case-dependent, so it runs
    // for real on every platform, Linux included.
    let live_path = device_b.root.path().join("Photo.jpg");
    std::fs::write(&live_path, b"original photo bytes").unwrap();
    wait_until(
        || {
            device_b
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(&group_id, "Photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(10),
    )
    .await;

    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(device_b.root.path()) {
        eprintln!(
            "skipping the collision-specific assertions: {} is case-sensitive here",
            device_b.root.path().display()
        );
        return;
    }

    // device_a must hold "Photo.jpg" on disk before the colliding sibling is
    // authored there: a device that learns of the sibling first holds both
    // names (each collides with the other's row) and never materializes
    // either, so there is no file of its own for the tombstone below to
    // remove and no live head for it to supersede. A slower filesystem
    // (Windows) lets the sibling win that race.
    wait_until(
        || {
            std::fs::read(device_a.root.path().join("Photo.jpg")).ok().as_deref()
                == Some(b"original photo bytes".as_slice())
        },
        Duration::from_secs(20),
    )
    .await;

    // "photo.jpg" is a colliding sibling known (held) from a create
    // collision, same mechanism as the tests above.
    commit_pure_dag_create(&device_a, &group_id, "photo.jpg", b"a completely different photo");
    publish_and_wake(&device_a, &group_id).await;
    wait_until_with_context(
        || {
            device_b
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(&group_id, "photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
        || {
            // Both roots and both index views: "the record never reached
            // device-b at all" and "it reached device-b but was not held"
            // are different bugs, and the on-disk entry list alone cannot
            // tell them apart -- a device that never received the record
            // and one that received it and correctly refused to write it
            // both show only the first file on disk.
            format!(
                "device-a root={} index={:?}; device-b root={} entries={:?} index={:?}",
                device_a.root.path().display(),
                index_paths(&device_a, &group_id),
                device_b.root.path().display(),
                real_entry_names(device_b.root.path()),
                index_paths(&device_b, &group_id),
            ) + &format!(
                " device-b disk_bytes={:?}",
                real_entry_names(device_b.root.path())
                    .iter()
                    .map(|name| (
                        name.clone(),
                        std::fs::read(device_b.root.path().join(name))
                            .map(|b| String::from_utf8_lossy(&b).to_string())
                            .unwrap_or_else(|e| format!("read_error={e}"))
                    ))
                    .collect::<Vec<_>>()
            )
        },
    )
    .await;

    // device_a commits a tombstone for "Photo.jpg" -- the live file's OWN
    // path, not the sibling's. Before this arrives, "Photo.jpg" was
    // created by a purely LOCAL edit on device_b and so was never routed
    // through the peer-materialize hazard check at all; `get_held_state`
    // transitioning to `Some` is therefore itself proof the tombstone
    // arrived and was processed (nothing else in this test ever calls
    // `set_held` for "Photo.jpg").
    // device_a must actually have received "Photo.jpg" before it deletes it:
    // `commit_pure_dag_tombstone` removes the authoring device's own on-disk
    // copy, and a removal that finds nothing there leaves device_a free to
    // materialize the file afterwards and re-propagate it as a fresh Put
    // that supersedes this very tombstone.
    wait_until(
        || {
            device_a
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(&group_id, "Photo.jpg")
                .unwrap()
                .is_some()
        },
        Duration::from_secs(20),
    )
    .await;

    commit_pure_dag_tombstone(&device_a, &group_id, "Photo.jpg");
    publish_and_wake(&device_a, &group_id).await;
    // Whether device_b admits and holds the tombstone depends on the platform
    // making the deletion durable. Where it cannot, the wait is skipped and
    // the safety assertions below still have to hold after a settle period.
    if yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the tombstone being admitted and held",
    ) {
        wait_until_with_context(
            || {
                native_head_gone(&device_b, &group_id, "Photo.jpg")
                    && device_b
                        .state
                        .replica_coordinator
                        .materialization_state_repository()
                        .get_held_state(&group_id, "Photo.jpg")
                        .unwrap()
                        .is_some()
            },
            Duration::from_secs(20),
            || {
                // Which half of the wait is unmet matters: "the tombstone
                // never arrived" and "it arrived but its target was never
                // held" are different bugs in different subsystems, and the
                // index row alone looks identical either way.
                format!(
                    "device-b never processed the tombstone: head_gone={:?} held={:?} {}",
                    native_head_gone(&device_b, &group_id, "Photo.jpg"),
                    device_b
                        .state
                        .replica_coordinator
                        .materialization_state_repository()
                        .get_held_state(&group_id, "Photo.jpg"),
                    index_summary(&device_b, &group_id, "Photo.jpg")
                )
            },
        )
        .await;
    } else {
        // The tombstone must have reached device_b before the settle window
        // means anything: a device that never received it also keeps its row
        // and bytes. Receipt is observable as the admitted removal, a hold,
        // or the projection obligation the admission arms.
        let received = || {
            native_head_gone(&device_b, &group_id, "Photo.jpg")
                || device_b
                    .state
                    .replica_coordinator
                    .materialization_state_repository()
                    .get_held_state(&group_id, "Photo.jpg")
                    .unwrap()
                    .is_some()
                || device_b
                    .state
                    .replica_coordinator
                    .sqlite()
                    .dag_lookup_projection_obligation(&group_id, "Photo.jpg")
                    .unwrap()
                    .is_some()
        };
        wait_until_with_context(received, Duration::from_secs(20), || {
            format!(
                "the tombstone never reached device-b: {}",
                index_summary(&device_b, &group_id, "Photo.jpg")
            )
        })
        .await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        eprintln!(
            "closed-gate arrival state: head_gone={} held={:?} obligation={:?} row_deleted={:?} \
             file_exists={} bytes={:?}",
            native_head_gone(&device_b, &group_id, "Photo.jpg"),
            device_b
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(&group_id, "Photo.jpg"),
            device_b
                .state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(&group_id, "Photo.jpg")
                .map(|o| o.map(|o| o.state)),
            device_b
                .state
                .replica_coordinator
                .file_index_repository()
                .get_file(&group_id, "Photo.jpg")
                .map(|r| r.map(|r| r.deleted)),
            live_path.exists(),
            std::fs::read(&live_path).ok().map(|b| String::from_utf8_lossy(&b).to_string()),
        );
    }

    let record = device_b
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, "Photo.jpg")
        .unwrap()
        .unwrap();
    assert!(
        !record.deleted,
        "Photo.jpg's own index row must not become deleted=true while its bytes are still on \
         disk -- that is exactly the divergence a later scan reads as a resurrection-worthy \
         local edit"
    );
    assert_eq!(
        std::fs::read(&live_path).unwrap(),
        b"original photo bytes",
        "a held tombstone must never physically delete the file it targets"
    );
}
