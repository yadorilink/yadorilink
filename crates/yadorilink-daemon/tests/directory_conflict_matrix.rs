//! A two-device matrix of DIRECTORY-level collision scenarios, run
//! through the real full daemon stack (directly-paired peer sessions
//! over loopback) -- complementary to `collision_matrix.rs`
//! (whose scenarios all collide on a single *file*), `monkey_chaos.rs`,
//! and `taguchi_collision_matrix.rs`, none of which exercise a directory
//! being renamed/deleted/created concurrently while it (or its contents)
//! are also being touched by the other device.
//!
//! Key background fact this whole file leans on (confirmed by reading
//! `local_change.rs`, `watcher.rs`, `materialization.rs`, and
//! `peer_session.rs` before writing any of this): **a directory is never,
//! itself, a tracked index entity.**
//! `local_change.rs::build_record_for_created_or_modified` explicitly
//! returns `None` for any non-file lstat ("directory event, or exotic
//! entry"), and `scan_existing_files`'s walker skips anything that isn't
//! a file or a symlink. `types::RecordKind::Directory` exists only as a
//! wire-compatibility enum value (`domain_record_kind_from_proto`/
//! `LocalFileMetaColumns::from_version_meta`) -- it is never assigned by any local
//! scan or watch path. Consequently there is no directory-level tombstone,
//! no "recursive delete" message, and no directory-rename decomposition
//! anywhere in this engine: every scenario below reduces, one way or
//! another, to how the *files* underneath a directory operation do or
//! don't individually generate their own fs-level events. That reduction
//! is straightforward for a recursive delete (`remove_dir_all` unlinks
//! each file individually -- one real `Removed` event per file, same as
//! `collision_matrix.rs`'s file-level scenarios) but is NOT straightforward
//! for a directory *rename* (a single fs-level rename of the directory
//! entry itself, which never touches its children's inodes or names, so
//! no fs event fires for them at all -- `watcher.rs`'s
//! `register_new_directory_tree`, run for the renamed-to side, only adds
//! *future* watches into the newly-appeared subtree, it never synthesizes
//! creation events for files already inside it). Scenarios 1 and 3 below
//! are written with that asymmetry front and center; see each one's own
//! doc comment for the specific reasoning and what is (and isn't) safe to
//! assert as a result.
//!
//! `TestDevice`/`setup_device`/`start_watching` are intentionally
//! duplicated from `collision_matrix.rs`/`monkey_chaos.rs`/
//! `taguchi_collision_matrix.rs` rather than shared -- matches this
//! codebase's existing convention of self-contained daemon integration
//! test binaries.

mod support;

#[path = "dst_support/namespace_oracle.rs"]
mod namespace_oracle;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
use support::{
    open_file_backed_replica_coordinator, wait_until, wait_until_with_context, TestAccount,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

use namespace_oracle::{check_trees_converge, disk_tree, sha256_hex, DiskNode, DiskTree};

// These cases drive real watchers, encrypted UDP sessions, and file-backed
// SQLite on both peers. In particular, macOS hosted runners can spend tens of
// seconds retrying transient SQLite lock contention. Keep the assertion exact,
// but give the same convergence budget as the other full-stack DAG tests.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(90);

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // This file's scenarios all drive concurrent multi-device writes and
    // conflict resolution under load, so `SyncState` is opened file-backed
    // WAL (production's concurrency model) rather than
    // `open_in_memory`'s shared-cache backend — see
    // `open_file_backed_replica_coordinator`'s doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
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
    // change-DAG emitter is wired and local edits actually propagate. Must run
    // after `DaemonState::new` and before `start_watching`'s
    // `LinkRuntimeController::start` — a key installed after the watch starts
    // would leave change emission off and nothing would propagate.
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
    let group_id = support::create_folder_group(&account, "directory-collision-group").await;
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

/// A recursive relative-path -> content-hash snapshot of everything under
/// `root`, for scenarios where the flat, non-recursive `real_entry_names`
/// (top-level only, by design -- see its own doc comment) isn't enough to
/// check nested directory contents.
fn recursive_snapshot(root: &Path) -> HashMap<String, String> {
    fn walk(base: &Path, current: &Path, out: &mut HashMap<String, String>) {
        let Ok(entries) = std::fs::read_dir(current) else { return };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME
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

/// Waits until neither device's own capture has anything pending or in flight (see
/// `support::quiescence`), so a directory rename or delete cannot race the daemon's file opens.
async fn wait_devices_quiescent(device_a: &TestDevice, device_b: &TestDevice, group_id: &str) {
    for device in [device_a, device_b] {
        support::quiescence::wait_quiescent(device.root.path(), &device.state, group_id).await;
    }
}

// --- Scenario 1: concurrent directory rename to different targets ---------

/// Both devices independently rename the same already-synced directory
/// (containing several files) to *different* new names at (effectively)
/// the same time.
///
/// This is deliberately NOT written as a nested version of
/// `collision_matrix.rs`'s `concurrent_rename_to_different_targets_both_survive`,
/// despite the superficially similar name, because the mechanism is not
/// analogous. A *file* rename fires a `RenameMode::From`/`To` pair against
/// that file's own tracked index row -- `process_event` decomposes it into
/// a real `Removed` (old path) + `CreatedOrModified` (new path) pair, so
/// the file-level scenario has a knowable shape. A *directory* rename is a
/// single fs-level rename of the directory entry itself: the files inside
/// it aren't touched (same inode, same name, same parent-relative
/// position) so the OS/notify backend never reports any event for them at
/// all. `watcher.rs`'s `register_new_directory_tree` (invoked for the
/// renamed-to path, since it's observed as a `CreatedOrModified` directory
/// event) only registers *future* watches into the newly-appeared
/// subtree -- it does not walk the subtree and synthesize "here are the
/// files already inside it" events. Nothing in the daemon's own link-runtime task wiring runs a
/// periodic full local rescan either (only an ignore-file change or a
/// genuine watcher-channel overflow trigger a `RescanRequired`
/// reconciliation scan — a large but fully-known event-count burst no
/// longer does, see `debounce.rs`'s own doc comment — and a single
/// directory rename is nowhere near either of those).
///
/// The upshot: whether (and how) the renamed directory's *contents* ever
/// propagate to the peer at all is a genuinely open question this test
/// exists to answer empirically, not a shape derivable from the existing
/// decomposition rules -- so this is a convergence-only assertion
/// (comparing the two devices' own recursive snapshots against *each
/// other*, not against a presumed "both new names, all files present"
/// shape), mirroring `taguchi_collision_matrix.rs`'s own philosophy for
/// shapes it can't fully predict either. A timeout here is itself a
/// meaningful, reproducible finding (the two devices never learn about
/// each other's rename), not a flake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_directory_rename_to_different_targets() {
    let _ = tracing_subscriber::fmt::try_init();
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-rename-rename-diff").await;

    let dir_a = device_a.root.path().join("shared_dir");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::write(dir_a.join("a.txt"), b"content a").unwrap();
    std::fs::write(dir_a.join("b.txt"), b"content b").unwrap();
    std::fs::write(dir_a.join("c.txt"), b"content c").unwrap();

    wait_until(|| device_b.root.path().join("shared_dir/c.txt").exists(), Duration::from_secs(10))
        .await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;

    std::fs::rename(
        device_a.root.path().join("shared_dir"),
        device_a.root.path().join("renamed-by-a"),
    )
    .unwrap();
    // Confirm the local rename itself actually succeeded at this point --
    // distinct from (and not implying) anything about the FINAL synced
    // state below, which the system's own lack of directory tracking
    // does not guarantee.
    assert!(!device_a.root.path().join("shared_dir").exists());

    std::fs::rename(
        device_b.root.path().join("shared_dir"),
        device_b.root.path().join("renamed-by-b"),
    )
    .unwrap();
    assert!(!device_b.root.path().join("shared_dir").exists());

    wait_until_with_context(
        || recursive_snapshot(device_a.root.path()) == recursive_snapshot(device_b.root.path()),
        SETTLE_TIMEOUT,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;
}

// --- Scenario 2: delete a directory while the peer adds a file inside it ---

/// Device A deletes an already-synced directory (with existing files)
/// entirely, while device B concurrently ADDS a brand-new file inside
/// that same directory -- racing the directory's disappearance.
///
/// Unlike scenario 1's rename, `std::fs::remove_dir_all` individually
/// unlinks every file inside the directory -- one real `unlink` syscall,
/// and therefore one real `Removed` fs event, per file, each against that
/// file's own tracked index row. So each pre-existing file genuinely gets
/// tombstoned (`process_event`'s `Removed` branch: `mark_deleted` fires
/// because `get_file` finds an existing row for it) and broadcast --
/// this is not the same propagation gap as scenario 1.
///
/// Checked `materialization.rs` and `peer_session.rs` directly for any
/// directory-level tombstone or recursive-delete concept ("rmdir"/
/// "remove_dir"/directory-tombstone handling): there is none.
/// `RecordKind::Directory` is the only directory-shaped thing either file
/// deals with, and it's a wire-compatibility value only
/// (`domain_record_kind_from_proto`/`LocalFileMetaColumns::from_version_meta`),
/// never assigned locally. So there is no "delete this whole directory"
/// message on the wire at all -- from the sync engine's point of view, a
/// directory delete is indistinguishable from "someone deleted these N
/// specific files that happen to share a parent path prefix". Device B's
/// brand-new file was never one of those N files, so it cannot be lost by
/// this deletion; and `chunker.rs`'s file-write helpers unconditionally
/// `create_dir_all(parent)` before writing, so the parent directory is
/// transparently recreated wherever it's needed to hold the survivor
/// (materializing B's new file back onto device A, whose own on-disk
/// "target_dir" no longer exists at that point).
///
/// Assertion shape used: the specific, reasoned outcome above, not a bare
/// convergence check -- the property that MUST hold is that the new
/// file's content is not silently lost on either device, and this test
/// pins down the exact final shape (both pre-existing files gone, the new
/// one present with its real content) that reasoning predicts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_directory_while_peer_adds_a_file_inside_it() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-delete-vs-add-inside").await;
    let _ = group_id;

    let dir_a = device_a.root.path().join("target_dir");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::write(dir_a.join("existing-1.txt"), b"existing content one").unwrap();
    std::fs::write(dir_a.join("existing-2.txt"), b"existing content two").unwrap();

    wait_until(
        || device_b.root.path().join("target_dir/existing-2.txt").exists(),
        Duration::from_secs(10),
    )
    .await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;

    std::fs::remove_dir_all(&dir_a).unwrap();
    std::fs::write(
        device_b.root.path().join("target_dir/new_from_b.txt"),
        b"brand new content from device b",
    )
    .unwrap();

    let new_file_hash = hex::encode(sha2::Sha256::digest(b"brand new content from device b"));

    wait_until_with_context(
        || {
            let a = recursive_snapshot(device_a.root.path());
            let b = recursive_snapshot(device_b.root.path());
            a == b && a.get("target_dir/new_from_b.txt") == Some(&new_file_hash)
        },
        SETTLE_TIMEOUT,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    let snap_a = recursive_snapshot(device_a.root.path());
    let snap_b = recursive_snapshot(device_b.root.path());
    assert_eq!(snap_a, snap_b);
    assert!(!snap_a.contains_key("target_dir/existing-1.txt"), "{snap_a:?}");
    assert!(!snap_a.contains_key("target_dir/existing-2.txt"), "{snap_a:?}");
    assert_eq!(snap_a.get("target_dir/new_from_b.txt"), Some(&new_file_hash));
}

// --- Scenario 3: a subdirectory rename races a child file edit ------------

/// Device A renames a subdirectory (containing `child.txt`) to a new
/// name, while device B -- unaware of A's rename -- concurrently edits
/// `child.txt`'s content via its own original nested path.
///
/// Per scenario 1's reasoning, A's rename never touches `child.txt`'s own
/// tracked index row at all (no fs event fires for it). Device B's edit,
/// by contrast, is an ordinary local edit against a path B's own index
/// still considers live -- a real `CreatedOrModified` event, chunked,
/// indexed, and broadcast normally. When that incoming update reaches
/// device A, A's own index *also* still considers "subdir/child.txt" live
/// (again: the rename never touched that row), so A treats it as an
/// ordinary incoming update to an existing path, and `materialize`'s
/// `create_dir_all(parent)` transparently recreates "subdir" (which A
/// physically renamed away) to hold it.
///
/// That specific mechanism is a reasoned prediction, not something this
/// test can fully verify without running it (deferred), so -- per the
/// same "don't presume a fully-derived shape" caution as scenario 1 --
/// this only asserts the one property that must hold regardless of the
/// exact resolution path: B's edited content is not silently lost. It
/// must appear *somewhere* in each device's final tree (the original
/// nested path, the renamed one, or a conflict copy), not "nowhere".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nested_rename_races_a_child_file_edit() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-nested-rename-vs-edit").await;

    let subdir_a = device_a.root.path().join("subdir");
    std::fs::create_dir_all(&subdir_a).unwrap();
    std::fs::write(subdir_a.join("child.txt"), b"original child content").unwrap();

    wait_until(|| device_b.root.path().join("subdir/child.txt").exists(), Duration::from_secs(10))
        .await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;

    std::fs::rename(
        device_a.root.path().join("subdir"),
        device_a.root.path().join("subdir-renamed"),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(
        device_b.root.path().join("subdir/child.txt"),
        b"edited by b, racing a's directory rename",
    )
    .unwrap();

    let edited_hash =
        hex::encode(sha2::Sha256::digest(b"edited by b, racing a's directory rename"));

    wait_until_with_context(
        || {
            recursive_snapshot(device_a.root.path()).values().any(|h| h == &edited_hash)
                && recursive_snapshot(device_b.root.path()).values().any(|h| h == &edited_hash)
        },
        SETTLE_TIMEOUT,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;
}

// --- Scenario 4: same-named new directory, non-overlapping contents -------

/// No prior sync state: both devices, at (effectively) the same time,
/// create a brand-new directory with the SAME name but DIFFERENT,
/// non-overlapping files inside (device A creates `newdir/only-a.txt`,
/// device B creates `newdir/only-b.txt`).
///
/// Since a directory is never its own tracked index entity (see this
/// file's header comment), this is not a collision at the sync-engine
/// level at all -- "newdir/only-a.txt" and "newdir/only-b.txt" are simply
/// two unrelated, non-overlapping file paths, each synced independently
/// and normally, with `chunker.rs`'s `create_dir_all(parent)`
/// transparently creating "newdir" on whichever device doesn't already
/// have it. This is therefore a confident, specific-outcome assertion
/// (not a convergence-only one, and not the "reduces to a conflict" shape
/// of scenario 5): both files must end up present under "newdir/" on both
/// devices, with no conflict copy and no data loss -- a same-named
/// directory collision with non-conflicting contents inside must merge,
/// not produce a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrently_creating_same_named_directory_with_different_files_inside() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-create-create-merge").await;
    let _ = group_id;

    std::fs::create_dir_all(device_a.root.path().join("newdir")).unwrap();
    std::fs::create_dir_all(device_b.root.path().join("newdir")).unwrap();
    std::fs::write(device_a.root.path().join("newdir/only-a.txt"), b"only on a originally")
        .unwrap();
    std::fs::write(device_b.root.path().join("newdir/only-b.txt"), b"only on b originally")
        .unwrap();

    wait_until_with_context(
        || {
            let a = recursive_snapshot(device_a.root.path());
            let b = recursive_snapshot(device_b.root.path());
            a == b && a.contains_key("newdir/only-a.txt") && a.contains_key("newdir/only-b.txt")
        },
        SETTLE_TIMEOUT,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    let snap_a = recursive_snapshot(device_a.root.path());
    assert!(!snap_a.keys().any(|k| is_conflict_copy(k)), "{snap_a:?}");
}

// --- Scenario 5: same-named new directory, a genuinely conflicting file ---

/// Same setup as scenario 4, but both devices write DIFFERENT content to
/// the SAME filename inside the same-named new directory
/// (`newdir/shared.txt`).
///
/// Again, the directory itself carries no identity at the sync-engine
/// level -- "newdir/shared.txt" is a single, ordinary file path, and two
/// devices independently creating it with unrelated version histories is
/// exactly the shape `collision_matrix.rs`'s scenario 1
/// (`concurrent_edit_edit_keeps_both_copies_as_original_plus_conflict_copy`)
/// already pins down, just one level deeper. Both contents must survive:
/// one under the original nested name, one as a conflict copy --
/// `conflict.rs`'s conflict-copy name builder preserves the directory
/// prefix (`<dir>{stem} (conflicted copy,...).<ext>`), so the copy stays
/// nested under "newdir/" rather than flattening to the sync root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrently_creating_same_named_directory_with_a_conflicting_file_inside() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the directory/file replacement",
    ) {
        return;
    }
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-create-create-conflict").await;
    let _ = group_id;

    std::fs::create_dir_all(device_a.root.path().join("newdir")).unwrap();
    std::fs::write(device_a.root.path().join("newdir/shared.txt"), b"from device a").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::create_dir_all(device_b.root.path().join("newdir")).unwrap();
    std::fs::write(
        device_b.root.path().join("newdir/shared.txt"),
        b"from device b, different and longer",
    )
    .unwrap();

    wait_until_with_context(
        || {
            let a = recursive_snapshot(device_a.root.path());
            let b = recursive_snapshot(device_b.root.path());
            a == b && a.contains_key("newdir/shared.txt") && a.keys().any(|k| is_conflict_copy(k))
        },
        SETTLE_TIMEOUT,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    let snap_a = recursive_snapshot(device_a.root.path());
    assert_eq!(snap_a.keys().filter(|k| is_conflict_copy(k)).count(), 1, "{snap_a:?}");
    assert!(
        snap_a.keys().filter(|k| is_conflict_copy(k)).all(|k| k.starts_with("newdir/")),
        "conflict copy should stay nested under newdir/: {snap_a:?}"
    );
}

// --- Directory-aware scenarios ---------------------------------------------
//
// Every scenario above compares file-only snapshots, so an empty directory
// left behind, or a path that is a directory on one device and a file on the
// other, reads as converged. The scenarios below compare the whole physical
// tree, directories included (`namespace_oracle::disk_tree`), against the
// exact tree the explicit-entry model predicts:
//
// * a directory needed only to hold surviving descendants is a structural
//   container; once nothing lives under it and no device created it on
//   purpose, it is gone;
// * deleting a directory, `rm -rf` included, deletes the entries the device
//   observed and nothing else, so a concurrent child survives;
// * a file and a directory that both want the same path keep both, the
//   file beside the directory under its conflict-copy name.
//
// The engine does not replicate directory entries yet, so the scenarios that
// need it are ignored with the capability each one waits for; the rename
// scenario and the materialization guard already hold and run normally.

/// What `author` wrote to `path` in the group's native state as `device` holds
/// it: one label per op (`put`/`delete`), in the author's sequence order.
fn ops_by_author_at(device: &TestDevice, group_id: &str, author: &str, path: &str) -> Vec<String> {
    let mut out = Vec::new();
    for delta in support::native_deltas(&device.state, group_id)
        .iter()
        .filter(|delta| delta.author.device.as_str() == author)
    {
        for op in delta.ops.iter().filter(|op| op.path.as_str() == path) {
            match (&op.put, op.removes.is_empty()) {
                (Some(_), _) => out.push("put".to_owned()),
                (None, false) => out.push("delete".to_owned()),
                (None, true) => {}
            }
        }
    }
    out
}

fn file_node(bytes: &[u8]) -> DiskNode {
    DiskNode::File { sha256: sha256_hex(bytes) }
}

fn tree_of(entries: Vec<(&str, DiskNode)>) -> DiskTree {
    entries.into_iter().map(|(p, n)| (p.to_string(), n)).collect()
}

/// Waits until both devices hold the same physical tree, directories
/// included, and `done` accepts it; returns that tree.
async fn settle_to_one_tree(
    device_a: &TestDevice,
    device_b: &TestDevice,
    done: impl Fn(&DiskTree) -> bool,
) -> DiskTree {
    wait_until_with_context(
        || {
            let a = disk_tree(device_a.root.path());
            a == disk_tree(device_b.root.path()) && done(&a)
        },
        SETTLE_TIMEOUT,
        || {
            format!(
                "device-a={:#?}\ndevice-b={:#?}",
                disk_tree(device_a.root.path()),
                disk_tree(device_b.root.path())
            )
        },
    )
    .await;
    let a = disk_tree(device_a.root.path());
    let b = disk_tree(device_b.root.path());
    let divergence = check_trees_converge(&[(0, a.clone()), (1, b)]);
    assert!(divergence.is_empty(), "{divergence:#?}");
    a
}

/// `rm -rf linux/` on one device must leave no empty `linux/` (or
/// `linux/arch/`) on the other: the peer created those only to hold files
/// that are now gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rm_rf_directory_removes_now_empty_directory_on_peer() {
    let (device_a, device_b, group_id) = two_synced_devices("dir-rm-rf-leaves-no-dir").await;

    let linux = device_a.root.path().join("linux");
    std::fs::create_dir_all(linux.join("arch")).unwrap();
    std::fs::write(linux.join("Makefile"), b"all:").unwrap();
    std::fs::write(linux.join("arch/setup.c"), b"int main;").unwrap();
    wait_until(
        || device_b.root.path().join("linux/arch/setup.c").exists(),
        Duration::from_secs(20),
    )
    .await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;

    std::fs::remove_dir_all(&linux).unwrap();
    let tree = settle_to_one_tree(&device_a, &device_b, |t| t.is_empty()).await;
    assert_eq!(tree, DiskTree::new());
}

/// An empty directory is an entry like any other: created on one device, it
/// appears on the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_directory_created_on_one_device_appears_on_peer() {
    let (device_a, device_b, _group_id) = two_synced_devices("dir-empty-dir-syncs").await;

    std::fs::create_dir(device_a.root.path().join("empty")).unwrap();
    let tree = settle_to_one_tree(&device_a, &device_b, |t| {
        t.get("empty").is_some_and(DiskNode::is_directory)
    })
    .await;
    assert_eq!(tree, tree_of(vec![("empty", DiskNode::fresh_directory())]));
}

/// An explicit empty directory removed on one device goes on the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rmdir_of_explicit_empty_directory_propagates() {
    let (device_a, device_b, _group_id) = two_synced_devices("dir-rmdir-propagates").await;

    std::fs::create_dir(device_a.root.path().join("empty")).unwrap();
    settle_to_one_tree(&device_a, &device_b, |t| {
        t.get("empty").is_some_and(DiskNode::is_directory)
    })
    .await;

    std::fs::remove_dir(device_a.root.path().join("empty")).unwrap();
    let tree = settle_to_one_tree(&device_a, &device_b, |t| t.is_empty()).await;
    assert_eq!(tree, DiskTree::new());
}

/// `rm -rf target_dir` on A races B creating `target_dir/new_from_b.txt`.
/// B's file was never observed by A's delete, so it survives, and so does
/// `target_dir` as its container; nothing else A deleted (the files, the
/// now-empty `sub/`) may linger on either device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_directory_vs_concurrent_child_keeps_child_and_container() {
    let (device_a, device_b, group_id) = two_synced_devices("dir-rm-rf-vs-child").await;

    let dir_a = device_a.root.path().join("target_dir");
    std::fs::create_dir_all(dir_a.join("sub")).unwrap();
    std::fs::write(dir_a.join("existing.txt"), b"existing").unwrap();
    std::fs::write(dir_a.join("sub/deep.txt"), b"deep").unwrap();
    wait_until(
        || device_b.root.path().join("target_dir/sub/deep.txt").exists(),
        Duration::from_secs(20),
    )
    .await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;

    std::fs::remove_dir_all(&dir_a).unwrap();
    std::fs::write(device_b.root.path().join("target_dir/new_from_b.txt"), b"new from b").unwrap();

    let want = tree_of(vec![
        ("target_dir", DiskNode::fresh_directory()),
        ("target_dir/new_from_b.txt", file_node(b"new from b")),
    ]);
    let tree = settle_to_one_tree(&device_a, &device_b, |t| *t == want).await;
    assert_eq!(tree, want);

    // `target_dir` now lives on both devices only as the container of B's
    // file. Neither device may author it back into existence: A wrote it
    // once (its mkdir) and deleted it, B never wrote it.
    for device in [&device_a, &device_b] {
        let a_ops = ops_by_author_at(device, &group_id, &device_a.device_id, "target_dir");
        assert_eq!(a_ops, ["put", "delete"], "A's ops on the container");
        let b_ops = ops_by_author_at(device, &group_id, &device_b.device_id, "target_dir");
        assert!(b_ops.is_empty(), "B authored the container it only holds: {b_ops:?}");
    }
}

/// A creates File `a`; B concurrently creates `a/x`. A filesystem cannot
/// hold both at `a`, and neither may be lost: `a` is the directory holding
/// `a/x`, and A's file sits beside it under its conflict-copy name.
///
/// B's `mkdir a` is an explicit entry of its own, and it may reach a device
/// before B's `a/x` does. File `a` and Directory `a` are then a same-path
/// conflict, and the Directory keeps `a` whichever ranks higher (DIR-1):
/// the file moves to its copy name, and a Directory is never copied, so the
/// tree is exactly these three entries in every arrival order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_vs_descendant_structural_conflict_keeps_both() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the directory/file replacement",
    ) {
        return;
    }
    let (device_a, device_b, _group_id) = two_synced_devices("dir-file-vs-descendant").await;

    std::fs::write(device_a.root.path().join("a"), b"file a").unwrap();
    std::fs::create_dir(device_b.root.path().join("a")).unwrap();
    std::fs::write(device_b.root.path().join("a/x"), b"file a/x").unwrap();

    let tree = settle_to_one_tree(&device_a, &device_b, |t| t.len() == 3).await;
    assert!(tree.get("a").is_some_and(DiskNode::is_directory), "{tree:#?}");
    assert_eq!(tree.get("a/x"), Some(&file_node(b"file a/x")), "{tree:#?}");
    let beside: Vec<(&String, &DiskNode)> =
        tree.iter().filter(|(p, _)| p.starts_with("a (") && is_conflict_copy(p)).collect();
    assert_eq!(beside.len(), 1, "{tree:#?}");
    assert_eq!(beside[0].1, &file_node(b"file a"), "{tree:#?}");
}

/// DIR-1 with the Directory arriving before `a/x`: B's empty `mkdir a`
/// races A's File `a`, and settles with the Directory at `a` and the file
/// beside it -- no empty directory copy. B's `a/x`, written afterwards,
/// lands in that directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_directory_keeps_its_name_against_a_file_before_and_after_its_child() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the directory/file replacement",
    ) {
        return;
    }
    let (device_a, device_b, _group_id) = two_synced_devices("dir-explicit-vs-file").await;

    std::fs::write(device_a.root.path().join("a"), b"file a").unwrap();
    std::fs::create_dir(device_b.root.path().join("a")).unwrap();

    let is_the_file_beside_a =
        |(p, n): (&String, &DiskNode)| p.starts_with("a (") && *n == file_node(b"file a");
    let tree = settle_to_one_tree(&device_a, &device_b, |t| {
        t.len() == 2 && t.iter().any(is_the_file_beside_a)
    })
    .await;
    assert!(tree.get("a").is_some_and(DiskNode::is_directory), "{tree:#?}");

    std::fs::write(device_b.root.path().join("a/x"), b"file a/x").unwrap();
    let tree = settle_to_one_tree(&device_a, &device_b, |t| {
        t.len() == 3 && t.get("a/x") == Some(&file_node(b"file a/x"))
    })
    .await;
    assert!(tree.get("a").is_some_and(DiskNode::is_directory), "{tree:#?}");
    assert!(tree.iter().any(is_the_file_beside_a), "{tree:#?}");
}

/// DIR-1 for a Symlink: A's symlink `a` races B's `mkdir a` and `a/x`. The
/// Directory keeps `a`, the link sits beside it under its copy name, and
/// nothing else is there.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_directory_keeps_its_name_against_a_symlink() {
    let (device_a, device_b, _group_id) = two_synced_devices("dir-explicit-vs-symlink").await;

    std::os::unix::fs::symlink("target", device_a.root.path().join("a")).unwrap();
    std::fs::create_dir(device_b.root.path().join("a")).unwrap();
    std::fs::write(device_b.root.path().join("a/x"), b"file a/x").unwrap();

    let tree = settle_to_one_tree(&device_a, &device_b, |t| t.len() == 3).await;
    assert!(tree.get("a").is_some_and(DiskNode::is_directory), "{tree:#?}");
    assert_eq!(tree.get("a/x"), Some(&file_node(b"file a/x")), "{tree:#?}");
    let beside: Vec<(&String, &DiskNode)> =
        tree.iter().filter(|(p, _)| p.starts_with("a (") && is_conflict_copy(p)).collect();
    assert_eq!(beside.len(), 1, "{tree:#?}");
    assert_eq!(beside[0].1, &DiskNode::Symlink { target: "target".to_string() }, "{tree:#?}");
}

/// A renames `d` to `e` while B creates `d/new`. The rename moves the
/// entries A observed; B's concurrent child stays under `d`, which survives
/// as its container. Green with file-only replication already (the rename
/// reaches the peer as per-file delete-and-put); it pins the tree that
/// directory entries must keep producing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directory_rename_across_two_devices_moves_explicit_entries_only() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the directory/file replacement",
    ) {
        return;
    }
    let (device_a, device_b, group_id) = two_synced_devices("dir-rename-vs-child").await;

    std::fs::create_dir(device_a.root.path().join("d")).unwrap();
    std::fs::write(device_a.root.path().join("d/f.txt"), b"moved").unwrap();
    wait_until(|| device_b.root.path().join("d/f.txt").exists(), Duration::from_secs(20)).await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;

    std::fs::rename(device_a.root.path().join("d"), device_a.root.path().join("e")).unwrap();
    std::fs::write(device_b.root.path().join("d/new.txt"), b"concurrent").unwrap();

    let want = tree_of(vec![
        ("d", DiskNode::fresh_directory()),
        ("d/new.txt", file_node(b"concurrent")),
        ("e", DiskNode::fresh_directory()),
        ("e/f.txt", file_node(b"moved")),
    ]);
    let tree = settle_to_one_tree(&device_a, &device_b, |t| *t == want).await;
    assert_eq!(tree, want);
}

/// After a peer's `rm -rf p` has settled, a fresh `mkdir p` is a new user
/// directory, not the old container coming back: it is captured as an
/// explicit entry and appears, empty, on the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mkdir_after_remote_rm_rf_of_same_path_is_captured_as_explicit() {
    let (device_a, device_b, group_id) = two_synced_devices("dir-mkdir-after-rm-rf").await;

    std::fs::create_dir(device_a.root.path().join("p")).unwrap();
    std::fs::write(device_a.root.path().join("p/f.txt"), b"f").unwrap();
    wait_until(|| device_b.root.path().join("p/f.txt").exists(), Duration::from_secs(20)).await;
    wait_devices_quiescent(&device_a, &device_b, &group_id).await;
    std::fs::remove_dir_all(device_a.root.path().join("p")).unwrap();
    settle_to_one_tree(&device_a, &device_b, |t| t.is_empty()).await;

    std::fs::create_dir(device_b.root.path().join("p")).unwrap();
    let want = tree_of(vec![("p", DiskNode::fresh_directory())]);
    let tree = settle_to_one_tree(&device_a, &device_b, |t| *t == want).await;
    assert_eq!(tree, want);
}

/// Guard, green today and required to stay green: materializing a peer's
/// nested file creates its parent directories on the receiver, and the
/// receiver's own capture must never author those (or anything else: the
/// receiver did nothing) as changes of its own. They are containers the
/// engine made, not user intent; authoring them would keep them alive after
/// the file is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_file_materialization_never_authors_a_directory_change() {
    let (device_a, device_b, group_id) = two_synced_devices("dir-materialize-no-author").await;

    std::fs::create_dir_all(device_a.root.path().join("nested/deeper")).unwrap();
    std::fs::write(device_a.root.path().join("nested/deeper/file.txt"), b"payload").unwrap();
    settle_to_one_tree(&device_a, &device_b, |t| {
        t.get("nested/deeper/file.txt") == Some(&file_node(b"payload"))
    })
    .await;
    // Past the watcher's debounce, so a capture of the created directories
    // would have landed in the history by now.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Not vacuous: B's history holds A's write of the file.
    let a_put =
        ops_by_author_at(&device_b, &group_id, &device_a.device_id, "nested/deeper/file.txt");
    assert_eq!(a_put, ["put"], "B never admitted A's change");
    let changes = support::native_deltas(&device_b.state, &group_id);
    let authored: Vec<_> =
        changes.iter().filter(|c| c.author.device.as_str() == device_b.device_id).collect();
    assert!(
        authored.is_empty(),
        "the receiver authored changes of its own after only materializing a peer's file: \
         {authored:#?}"
    );
}
