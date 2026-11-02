#![cfg(test)]
//! What the namespace makes reconcile do on disk is never captured as a
//! change of this device's own.
//!
//! When a peer's `a/x` arrives while this device holds its own File `a`,
//! reconcile moves the file beside the new directory under its
//! conflict-copy name. Capture then sees File `a` gone from its name and a
//! new file it never wrote. Were it to read that as the user's doing, it
//! would sign a Delete of `a` for every device (and a Put of the copy),
//! turning a local, derived arrangement into a replicated loss. Likewise a
//! directory this device keeps only as a container -- one it created, or
//! an explicit directory a peer deleted while a child still lives -- is
//! never authored back.

use super::growing_file_projection_tests::{Harness, GROUP, LOCAL_DEVICE};
use super::*;
use std::collections::BTreeSet;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_sync_sqlite::structural_origin::StructuralOriginStatus;

fn put(path: &str, version: VersionHash) -> Op {
    Op::Put { path: SyncPath(path.into()), version }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

/// Emits a peer's change carrying `ops` on top of everything this device
/// holds, storing `versions` first.
fn remote_change(h: &Harness, ops: Vec<Op>, versions: &[FileVersion]) {
    h.state
        .database()
        .write(|conn| {
            for version in versions {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
    crate::test_support::remote_admission_fixture::admit_remote_ops(
        &h.state,
        GROUP,
        "device-remote",
        &ops,
        crate::test_support::remote_admission_fixture::Basis::CurrentHeads,
    );
}

/// Stores `bytes` as a version whose blocks this device holds, by
/// capturing them under a scratch name.
async fn stored_version(h: &Harness, scratch: &str, bytes: &[u8]) -> VersionHash {
    std::fs::write(h.path(scratch), bytes).unwrap();
    assert!(matches!(h.capture(scratch).await, LocalChangeOutcome::FileChanged(_)));
    VersionHash(h.own_head(scratch).content.unwrap().version_hash)
}

/// Every native delta this device authored, as `(hash, delta)`.
fn own_deltas(
    h: &Harness,
) -> Vec<([u8; 32], yadorilink_replica_domain::signed_delta::NativeDelta)> {
    h.all_deltas().into_iter().filter(|(_, delta)| delta.author.device.0 == LOCAL_DEVICE).collect()
}

fn own_change_count(h: &Harness) -> usize {
    own_deltas(h).len()
}

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

async fn settle(h: &Harness, paths: &[&str]) {
    let paths: BTreeSet<String> = paths.iter().map(|p| p.to_string()).collect();
    for _ in 0..3 {
        let attempt = h
            .convergence
            .reconcile_paths_directly(&driver(h), GROUP, paths.clone())
            .await
            .unwrap()
            .expect("sanity: the pass must actually run");
        if attempt.retry.is_empty() {
            return;
        }
    }
    panic!("{paths:?} did not settle");
}

/// Every name capture could be told about, then a full scan: none of it
/// may author anything.
async fn capture_everything(h: &Harness, names: &[&str]) {
    for name in names {
        h.capture(name).await;
    }
    h.scan();
}

/// A peer deletes explicit directory `d` while `d/f` lives: `d` stays as
/// the child's container, adopted as structural so it is never read as a
/// user's directory, and a full scan authors nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remotely_deleted_explicit_dir_with_live_child_is_not_reauthored_by_full_scan() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let h = Harness::new(true);
    let f = stored_version(&h, "scratch-f", b"a child that outlives its directory").await;
    let directory = FileVersion::directory();
    remote_change(&h, vec![put("d", directory.version_hash), put("d/f", f)], &[directory]);
    settle(&h, &["d", "d/f"]).await;
    let before = own_change_count(&h);

    remote_change(&h, vec![delete("d")], &[]);
    settle(&h, &["d"]).await;

    assert!(h.path("d").is_dir());
    assert_eq!(std::fs::read(h.path("d/f")).unwrap(), b"a child that outlives its directory");
    let origin = h.state.sqlite().dag_structural_directory_origin(GROUP, "d").unwrap();
    let observed =
        yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&h.path("d")).ok();
    assert_eq!(
        origin.status(
            observed.as_ref(),
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine
        ),
        StructuralOriginStatus::Structural,
        "the kept directory must be adopted as structural"
    );
    capture_everything(&h, &["d", "d/f"]).await;
    assert_eq!(own_change_count(&h), before);
}

// --- Write-through: a user's operation on a relocated leaf ---
//
// The copy name a relocated File or Symlink sits under is the projection's,
// not an entry anyone authored. Deleting or editing it is the user acting
// on the source entry: `Delete(a)` / `Put(a)`, never an op at the copy
// name.

/// A symlink on disk where the index has a captured File, which the flush
/// did not capture, is local state displacement must not unlink.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn displacing_a_leaf_keeps_a_symlink_the_flush_did_not_capture() {
    let h = Harness::new(false);
    std::fs::write(h.path("a"), b"captured").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    std::fs::remove_file(h.path("a")).unwrap();
    std::os::unix::fs::symlink("elsewhere", h.path("a")).unwrap();

    let cleared = h.convergence.displace_leaf_for_directory(GROUP, "a").await.unwrap();

    assert!(!cleared, "an uncaptured symlink must not be displaced");
    assert!(std::fs::symlink_metadata(h.path("a")).unwrap().file_type().is_symlink());
}

/// Displacing a captured leaf makes the unlink durable before the row is erased.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn displacing_a_leaf_is_durable_before_the_index_row_is_erased() {
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"captured").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (state, observed, path) = (h.state.clone(), observed.clone(), h.path("a"));
        super::removal_ordering_probe::arm(h.path("a"), move || {
            let live = state.get_file(GROUP, "a").unwrap().is_some_and(|row| !row.deleted);
            observed.lock().unwrap().push((live, std::fs::symlink_metadata(&path).is_err()));
        });
    }

    let cleared = h.convergence.displace_leaf_for_directory(GROUP, "a").await.unwrap();

    assert!(cleared, "sanity: the captured leaf is displaced");
    assert_eq!(*observed.lock().unwrap(), vec![(true, true)]);
}

// --- A name given up for descendants keeps the version it gave up ---
//
// The leaf a sync moves out of a name its descendants need is a version a sync removes: its bytes
// go into the store first, its row is kept as history under a current tombstone, and nothing about
// it is authored for anyone else.

/// Takes `blocks` out of the store, so that afterwards only the user's file holds them.
#[cfg(unix)]
fn take_out_of_the_store(h: &Harness, blocks: &[yadorilink_replica_domain::file::BlockInfo]) {
    use yadorilink_local_storage::BlockStore;
    for block in blocks {
        h.store.delete(&hex::encode(&block.hash)).unwrap();
    }
}

#[cfg(unix)]
fn kept_in_the_store(h: &Harness, blocks: &[yadorilink_replica_domain::file::BlockInfo]) -> bool {
    let state = Arc::clone(&h.state);
    super::version_retention::version_kept_in_store(
        h.store.as_ref(),
        &move |hashes: &[Vec<u8>]| state.group_has_block_provenance_batch(GROUP, hashes),
        blocks,
    )
    .unwrap()
}

/// The version a leaf had when a sync made it give up its name stays restorable, and the row that
/// claimed the name is the current tombstone of a retained chain, not a gap in the index.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leaf_given_up_for_descendants_stays_restorable() {
    use yadorilink_replica_domain::session_state::VersionState;
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"the file whose name descendants need").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, "a").unwrap().unwrap().blocks;
    take_out_of_the_store(&h, &blocks);
    assert!(!kept_in_the_store(&h, &blocks), "fixture: only the file holds the version");

    let cleared = h.convergence.displace_leaf_for_directory(GROUP, "a").await.unwrap();

    assert!(cleared, "sanity: the captured leaf is displaced");
    assert!(std::fs::symlink_metadata(h.path("a")).is_err(), "the leaf is gone from the disk");
    assert!(kept_in_the_store(&h, &blocks), "the version it gave up is in the store");
    let versions = h.state.sqlite().dag_list_versions(GROUP, "a").unwrap();
    let current = versions.iter().find(|v| v.state == VersionState::Current).unwrap();
    assert!(current.deleted, "the name is claimed by a current tombstone, not by nothing");
    let kept = versions.iter().find(|v| v.state == VersionState::Trashed).unwrap();
    assert_eq!(kept.blocks, blocks, "the version it gave up is retained as history");
}

/// Nothing the displacement does is authored as a change of this device's own: no change is
/// signed, none removes anything at the name, the file's native head is untouched, and a full scan
/// authors nothing for the name afterwards. A delete signed here would reach every other device
/// and remove their file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn giving_up_a_name_authors_no_delete_for_other_devices() {
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"a file other devices hold too").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let head_before = h.own_head("a").change_hash;
    let before = own_change_count(&h);

    // The production arrangement: the leaf goes, the directory its descendants need is made and
    // adopted as structural.
    settle_structural_container_for(&h, "a").await;
    assert!(h.path("a").is_dir(), "sanity: the name is now the directory");
    capture_everything(&h, &["a"]).await;

    assert_eq!(own_change_count(&h), before, "no change was signed, so no delete can be sent");
    assert!(
        own_deltas(&h).iter().all(|(_, delta)| delta.ops.iter().all(|op| op.removes.is_empty())),
        "no signed change removes anything"
    );
    assert_eq!(h.own_head("a").change_hash, head_before, "the file's head is untouched");
}

#[cfg(unix)]
async fn settle_structural_container_for(h: &Harness, name: &str) {
    let result = h.convergence.settle_structural_container(GROUP, name).await.unwrap();
    assert!(
        matches!(result, super::MaterializeResult::Settled(_)),
        "the container settles: {result:?}"
    );
}

/// The rewind planner still sees the name: a rewind to a time when the file was there brings it
/// back, instead of the path having dropped out of every plan.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_given_up_is_still_in_the_rewind_plan() {
    use yadorilink_replica_domain::rewind::RewindPathAction;
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"a file a rewind should be able to bring back").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let version_hash = h.state.get_file(GROUP, "a").unwrap().map(|_| ()).map(|_| ());
    assert!(version_hash.is_some());
    let while_the_file_was_there =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            as i64;
    std::thread::sleep(std::time::Duration::from_millis(5));

    assert!(h.convergence.displace_leaf_for_directory(GROUP, "a").await.unwrap());

    let plan =
        h.state.sqlite().compute_rewind_plan(GROUP, while_the_file_was_there, &|_| false).unwrap();
    let entry =
        plan.entries.iter().find(|entry| entry.path == "a").expect("the path is in the plan");
    assert!(
        matches!(entry.action, RewindPathAction::Create { .. }),
        "a rewind brings the file back: {:?}",
        entry.action
    );
}

/// The explicit directory entry a sync retires to a structural directory leaves the chain behind it
/// in place: its row becomes history under a current tombstone, and is not erased.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retired_directory_entry_keeps_its_row_as_history() {
    use yadorilink_replica_domain::session_state::VersionState;
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let h = Harness::new(true);
    let f = stored_version(&h, "scratch-f", b"a child that outlives its directory").await;
    let directory = FileVersion::directory();
    remote_change(&h, vec![put("d", directory.version_hash), put("d/f", f)], &[directory]);
    settle(&h, &["d", "d/f"]).await;

    remote_change(&h, vec![delete("d")], &[]);
    settle(&h, &["d"]).await;

    let versions = h.state.sqlite().dag_list_versions(GROUP, "d").unwrap();
    assert!(
        versions.iter().any(|v| v.state == VersionState::Current && v.deleted),
        "the name is claimed by a current tombstone: {versions:?}"
    );
    assert!(
        versions
            .iter()
            .any(|v| v.state == VersionState::Trashed || v.state == VersionState::Superseded),
        "the directory entry's own row is kept as history: {versions:?}"
    );
}

/// The name's own row is a current tombstone while a child lives inside the directory: the
/// container settles again, a full scan authors nothing, and nothing reads the combination as an
/// error.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_current_tombstone_next_to_a_live_child_is_not_an_error() {
    use yadorilink_replica_domain::session_state::VersionState;
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"the file whose name the child needs").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    settle_structural_container_for(&h, "a").await;
    std::fs::write(h.path("a/x"), b"a child written inside a").unwrap();
    assert!(matches!(h.capture("a/x").await, LocalChangeOutcome::FileChanged(_)));
    let before = own_change_count(&h);

    settle_structural_container_for(&h, "a").await;
    capture_everything(&h, &["a", "a/x"]).await;

    assert_eq!(own_change_count(&h), before, "settling again and scanning author nothing");
    assert_eq!(std::fs::read(h.path("a/x")).unwrap(), b"a child written inside a");
    let versions = h.state.sqlite().dag_list_versions(GROUP, "a").unwrap();
    assert!(
        versions.iter().any(|v| v.state == VersionState::Current && v.deleted),
        "the name's own row is a current tombstone next to its live child: {versions:?}"
    );
    assert!(h.state.get_file(GROUP, "a/x").unwrap().is_some_and(|row| !row.deleted));
}

/// An editor saves over the file while the version it holds is being kept: the name is not given
/// up, and the edit stays.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leaf_edited_while_its_version_is_being_kept_does_not_give_up_its_name() {
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"the file whose name descendants need").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, "a").unwrap().unwrap().blocks;
    take_out_of_the_store(&h, &blocks);
    let edited: &[u8] = b"an edit saved while the old version was being kept";
    {
        let path = h.path("a");
        super::removal_ordering_probe::arm_after_proof(path.clone(), move || {
            let replacement = path.with_extension("tmp-save");
            std::fs::write(&replacement, edited).unwrap();
            std::fs::rename(&replacement, &path).unwrap();
        });
    }

    let cleared = h.convergence.displace_leaf_for_directory(GROUP, "a").await.unwrap();

    assert!(!cleared, "the name is not given up while the file changed under the proofs");
    assert_eq!(std::fs::read(h.path("a")).unwrap(), edited, "the edit is still there");
}
