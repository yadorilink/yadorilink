#![cfg(test)]
//! The rebootstrap freeze at the executor.
//!
//! While a rebootstrap freezes a group (see
//! `yadorilink_sync_sqlite::native_rebootstrap::group_frozen`), nothing may write,
//! delete, rename or replace an object of it, by any lane: the disk bytes, the
//! mode, the mtime and the index row stay as they are, and a local capture
//! authors nothing. The work is deferred, not dropped: after the freeze ends the
//! same pass reaches the intended state, and the edits made meanwhile, which
//! were never authored, are captured by the scan that follows.
//!
//! The remote changes are real signed deltas admitted through native admission
//! and the projection is the production reconcile pass, as in
//! `delete_projection_tests`.

use super::growing_file_projection_tests::{Harness, GROUP};
use super::*;
use crate::test_support::remote_admission_fixture::{admit_remote, delete, put, RemoteOp};
use crate::test_support::{freeze_group, unfreeze_group};
use std::collections::BTreeSet;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::ids::{DeltaHash, VersionHash};

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

async fn reconcile(h: &Harness, paths: &[&str]) -> ProjectionAttempt {
    h.convergence
        .reconcile_paths_directly(
            &driver(h),
            GROUP,
            paths.iter().map(|path| path.to_string()).collect::<BTreeSet<_>>(),
        )
        .await
        .unwrap()
        .expect("sanity: the pass must actually run")
}

/// Another device's next delta, admitted here.
fn admit_from(h: &Harness, device: &str, ops: Vec<RemoteOp>) {
    let versions: Vec<_> = ops
        .iter()
        .filter_map(|op| match op {
            RemoteOp::Put { version, .. } => {
                Some(h.state.dag_get_file_version(GROUP, version).unwrap().expect("stored here"))
            }
            RemoteOp::Delete { .. } => None,
        })
        .collect();
    admit_remote(&h.state, GROUP, device, ops, &versions);
}

fn freeze(h: &Harness) {
    freeze_group(&h.state, GROUP);
}

fn unfreeze(h: &Harness) {
    unfreeze_group(&h.state, GROUP);
}

/// A file written and captured here; returns this device's head hash.
async fn captured(h: &Harness, rel: &str, bytes: &[u8]) -> DeltaHash {
    if let Some(parent) = h.path(rel).parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(h.path(rel), bytes).unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    DeltaHash(h.own_head(rel).change_hash)
}

/// The version of a file other devices could write: captured here from a
/// scratch file so its content is held.
async fn a_version_held_here(h: &Harness, name: &str, bytes: &[u8]) -> VersionHash {
    std::fs::write(h.path(name), bytes).unwrap();
    assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
    VersionHash(h.own_head(name).content.unwrap().version_hash)
}

/// Everything about `rel` the freeze promises to leave alone.
#[derive(Debug, PartialEq)]
struct Standing {
    disk: Option<(Vec<u8>, u32, std::time::SystemTime)>,
    row: Option<yadorilink_replica_domain::file::FileRecord>,
}

fn standing(h: &Harness, rel: &str) -> Standing {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    let disk = std::fs::symlink_metadata(h.path(rel)).ok().map(|meta| {
        #[cfg(unix)]
        let mode = meta.permissions().mode();
        #[cfg(not(unix))]
        let mode = 0;
        (std::fs::read(h.path(rel)).unwrap_or_default(), mode, meta.modified().unwrap())
    });
    Standing { disk, row: h.state.get_file(GROUP, rel).unwrap() }
}

fn exists(h: &Harness, rel: &str) -> bool {
    std::fs::symlink_metadata(h.path(rel)).is_ok()
}

const REMOTE: &str = "remote-device";
const OTHER_REMOTE: &str = "other-remote-device";

/// What a delta set authored beyond `known` touches.
fn authored_since(h: &Harness, known: &BTreeSet<[u8; 32]>) -> Vec<String> {
    h.all_deltas()
        .iter()
        .filter(|(hash, _)| !known.contains(hash))
        .flat_map(|(_, delta)| delta.ops.iter().map(|op| op.path.as_str().to_owned()))
        .collect()
}

fn known_deltas(h: &Harness) -> BTreeSet<[u8; 32]> {
    h.all_deltas().into_iter().map(|(hash, _)| hash).collect()
}

// --- upstream changes: the content-write and tombstone lanes ----------------------------------

/// An upstream edit is not written over the object there, whether or not the user
/// has changed it; once the freeze ends the same pass writes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_edit_is_deferred_until_the_freeze_ends() {
    let h = Harness::new(true);
    let seen = captured(&h, "d/p", b"the version this device holds").await;
    let newer = a_version_held_here(&h, "scratch.bin", b"the version a peer wrote").await;
    admit_from(&h, REMOTE, vec![put("d/p", newer, vec![seen])]);
    std::fs::write(h.path("d/p"), b"an edit nobody has captured").unwrap();
    freeze(&h);
    let before = standing(&h, "d/p");

    for _ in 0..3 {
        let attempt = reconcile(&h, &["d/p"]).await;
        assert!(!attempt.is_settled("d/p"), "a frozen group is not settled");
    }

    assert_eq!(standing(&h, "d/p"), before, "the frozen object or its row changed");
    assert_eq!(std::fs::read(h.path("d/p")).unwrap(), b"an edit nobody has captured");

    unfreeze(&h);
    std::fs::write(h.path("d/p"), b"the version this device holds").unwrap();
    for _ in 0..3 {
        if reconcile(&h, &["d/p"]).await.is_settled("d/p") {
            break;
        }
    }
    assert_eq!(std::fs::read(h.path("d/p")).unwrap(), b"the version a peer wrote");
}

/// A removal, whole or as part of a recursive removal of its tree, removes nothing
/// under the freeze; after it the deferred delete runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_delete_is_deferred_until_the_freeze_ends() {
    let h = Harness::new(true);
    let p = captured(&h, "d/p", b"p, seen").await;
    let q = captured(&h, "d/q", b"q, seen").await;
    admit_from(&h, REMOTE, vec![delete("d/p", vec![p]), delete("d/q", vec![q])]);
    std::fs::write(h.path("d/p"), b"p, edited here, uncaptured").unwrap();
    freeze(&h);
    let before = (standing(&h, "d/p"), standing(&h, "d/q"));

    for _ in 0..3 {
        reconcile(&h, &["d/p", "d/q", "d"]).await;
    }

    assert_eq!((standing(&h, "d/p"), standing(&h, "d/q")), before, "a frozen object changed");

    unfreeze(&h);
    std::fs::write(h.path("d/p"), b"p, seen").unwrap();
    for _ in 0..3 {
        reconcile(&h, &["d/p", "d/q", "d"]).await;
    }
    assert!(!exists(&h, "d/p") && !exists(&h, "d/q"), "the deferred deletes never ran");
}

/// Two concurrent heads at a path: nothing is placed under the freeze and the
/// loser's head is not moved; after it the fork is authored and both are placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn contested_heads_are_not_forked_or_placed_until_the_freeze_ends() {
    let h = Harness::new(true);
    let a = a_version_held_here(&h, "scratch-a.bin", b"written by one peer").await;
    let b = a_version_held_here(&h, "scratch-b.bin", b"written by the other peer").await;
    admit_from(&h, REMOTE, vec![put("d/p", a, Vec::new())]);
    admit_from(&h, OTHER_REMOTE, vec![put("d/p", b, Vec::new())]);
    freeze(&h);

    for _ in 0..3 {
        reconcile(&h, &["d/p"]).await;
    }

    let placed = |h: &Harness| -> usize {
        std::fs::read_dir(h.path("d")).map_or(0, |entries| entries.filter_map(|e| e.ok()).count())
    };
    assert_eq!(placed(&h), 0, "something was placed under the freeze");
    assert!(h.try_fork_contests().is_err(), "a fork was authored under the freeze");

    unfreeze(&h);
    for _ in 0..4 {
        reconcile(&h, &["d/p"]).await;
    }
    assert_eq!(placed(&h), 0, "a contested path is placed only once it is forked");
    h.fork_own_contests();
    let paths = h.head_paths();
    for _ in 0..4 {
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        reconcile(&h, &paths).await;
    }
    assert_eq!(placed(&h), 2, "after the fork the winner and the copy are placed");
}

/// A fork authoring that fails part-way leaves nothing behind: no frontier position of this
/// device names a delta whose body is not stored (a peer asking for that range is refused,
/// and takes it for lost history).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_fork_authoring_leaves_no_frontier_position_without_its_delta() {
    let h = Harness::new(true);
    let a = a_version_held_here(&h, "scratch-a.bin", b"written by one peer").await;
    let b = a_version_held_here(&h, "scratch-b.bin", b"written by the other peer").await;
    admit_from(&h, REMOTE, vec![put("d/p", a, Vec::new())]);
    admit_from(&h, OTHER_REMOTE, vec![put("d/p", b, Vec::new())]);
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.execute_batch(&format!(
                "CREATE TRIGGER fail_body BEFORE INSERT ON native_delta_bodies \
                 WHEN NEW.author = '{}' BEGIN SELECT RAISE(ABORT, 'injected'); END;",
                super::growing_file_projection_tests::LOCAL_DEVICE
            ))?)
        })
        .unwrap();

    assert!(h.try_fork_contests().is_err(), "the injected failure did not surface");

    let unbacked: i64 = h
        .state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM native_author_frontier f WHERE f.author = ?1 AND NOT EXISTS ( \
                     SELECT 1 FROM native_delta_bodies b WHERE b.group_id = f.group_id \
                     AND b.author = f.author AND b.incarnation = f.incarnation AND b.seq = f.seq)",
                [super::growing_file_projection_tests::LOCAL_DEVICE],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(unbacked, 0, "a frontier position was committed without its delta");
}

// --- local capture --------------------------------------------------------------------------------

/// A local edit made during the freeze is not authored by any intake: not an
/// event, a flush, a scan, the dirty journal's redrive. It stays on disk, and the
/// scan after the freeze captures it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_edit_during_the_freeze_is_captured_after_the_freeze() {
    let h = Harness::new(false);
    captured(&h, "kept", b"before the freeze").await;
    let known = known_deltas(&h);
    freeze(&h);
    std::fs::write(h.path("kept"), b"edited during the freeze").unwrap();
    std::fs::write(h.path("unlisted"), b"made during the freeze").unwrap();

    assert!(matches!(h.capture("kept").await, LocalChangeOutcome::None), "an event authored");
    assert!(matches!(h.capture("unlisted").await, LocalChangeOutcome::None));
    h.capture_flush(&["kept", "unlisted"]).await;
    h.scan();
    h.redrive().await;

    assert!(authored_since(&h, &known).is_empty(), "an edit was authored under the freeze");
    assert_eq!(std::fs::read(h.path("kept")).unwrap(), b"edited during the freeze");

    unfreeze(&h);
    h.scan();
    h.capture_flush(&["kept", "unlisted"]).await;
    h.redrive().await;

    let mut authored = authored_since(&h, &known);
    authored.sort();
    assert_eq!(authored, vec!["kept".to_string(), "unlisted".to_string()]);
}

/// What a startup scan reads as an offline deletion is not authored under the
/// freeze either, and is captured after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_deletion_during_the_freeze_is_captured_after_the_freeze() {
    let h = Harness::new(false);
    captured(&h, "d/p", b"will be removed from the disk").await;
    captured(&h, "d/q", b"will be removed too").await;
    let known = known_deltas(&h);
    freeze(&h);
    std::fs::remove_dir_all(h.path("d")).unwrap();

    h.scan();
    h.capture_flush(&["d", "d/p"]).await;
    h.redrive().await;

    assert!(authored_since(&h, &known).is_empty(), "a deletion was authored under the freeze");

    unfreeze(&h);
    h.scan();
    h.capture_flush(&["d", "d/p", "d/q"]).await;
    h.redrive().await;

    let authored: BTreeSet<String> = authored_since(&h, &known).into_iter().collect();
    assert!(authored.contains("d/p") && authored.contains("d/q"), "{authored:?}");
}

// --- the reconciliation pass and the sweeps ---------------------------------------------------

/// The held-path reconciliation moves a divergent disk object aside as a conflict
/// copy and releases the hold, which is a write the freeze forbids: the pass does
/// not look at the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_held_path_reconciliation_does_not_run_while_the_group_is_frozen() {
    let h = Harness::new(true);
    captured(&h, "d/p", b"the row's version").await;
    std::fs::write(h.path("d/p"), b"an edit the reconciliation would move aside").unwrap();
    h.state.held_path_repository().hold_unauthorable_local_edit(GROUP, "d/p").unwrap();
    freeze(&h);
    let before = standing(&h, "d/p");

    for _ in 0..2 {
        tokio::task::block_in_place(|| {
            yadorilink_filesystem_sync::held_path_reconcile::reconcile_held_paths(
                h.state.as_ref(),
                &h.path(""),
                GROUP,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        });
    }

    assert_eq!(standing(&h, "d/p").disk, before.disk, "the pass moved the object aside");
    assert!(
        h.state.held_path_repository().is_held(GROUP, "d/p").unwrap(),
        "the pass released the hold behind the rebootstrap's back"
    );
    assert_eq!(std::fs::read_dir(h.path("d")).unwrap().count(), 1, "a conflict copy was made");
}

/// The freeze is the journal's, so it is a table: it survives the process, and it
/// is one group's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_freeze_is_durable_and_per_group() {
    let h = Harness::new(false);
    freeze(&h);
    let held = h.state.held_path_repository();
    assert!(held.group_frozen(GROUP).unwrap());
    assert!(!held.group_frozen("another-group").unwrap());
    unfreeze(&h);
    assert!(!held.group_frozen(GROUP).unwrap());
}

// --- the lanes' shared step and the hydration entry ------------------------------------------

/// Every lane takes the path's mutation fence inside the path lock before its
/// first write; under the freeze that step refuses every path of the group, and
/// the fence does not move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lane_cannot_take_a_mutation_fence_in_a_frozen_group() {
    let h = Harness::new(false);
    freeze(&h);
    for path in ["d/p", "d", "anywhere"] {
        let refused = h.state.dag_bump_mutation_fence(GROUP, path, "test");
        assert!(
            matches!(&refused, Err(error) if error.to_string().contains("frozen")),
            "{path}: {refused:?}"
        );
    }
    unfreeze(&h);
    h.state.dag_bump_mutation_fence(GROUP, "d/p", "test").unwrap();
}

// --- a restart in the middle of a rebootstrap ------------------------------------------------------

/// The state a crash leaves after the originals were quarantined and before the
/// install: the journal says `quarantining`, and the root has lost a file the old
/// native state still has a head for.
fn crashed_while_quarantining(h: &Harness) {
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_rebootstrap::set_journal_for_test(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                "quarantining",
                "00000000000000000000000000000001",
            );
            Ok(())
        })
        .unwrap();
}

/// The freeze is durable state every worker reads, so a restart needs nothing
/// restored before it starts: the startup scan, the capture backlog, the
/// reconcile pass and the repair sweep all find the group frozen. What they would
/// read as the user's deletion of a quarantined file, or as a file to put back,
/// they leave alone until the rebootstrap has finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_after_quarantine_before_install_restart_runs_no_capture_or_materialization_until_finish(
) {
    let h = Harness::new(true);
    let base = captured(&h, "d/p", b"the old state's version").await;
    let newer = a_version_held_here(&h, "scratch.bin", b"what the target holds").await;
    admit_from(&h, REMOTE, vec![put("d/p", newer, vec![base])]);
    let known = known_deltas(&h);
    crashed_while_quarantining(&h);
    // The quarantine had removed the original.
    std::fs::remove_file(h.path("d/p")).unwrap();
    let row_before = h.state.get_file(GROUP, "d/p").unwrap();

    // The restart: the same work every start does, before anything else is told.
    h.scan();
    h.redrive().await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap();
    tokio::task::block_in_place(|| {
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            h.state.as_ref(),
            &store,
            &h.path(""),
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
    })
    .expect("the repair sweep must go on past a frozen group, not abort");
    for _ in 0..3 {
        reconcile(&h, &["d/p", "d"]).await;
    }

    let authored = authored_since(&h, &known);
    assert!(authored.is_empty(), "the restart authored {authored:?} under the old incarnation");
    assert!(!exists(&h, "d/p"), "the restart put a file back under the freeze");
    assert_eq!(h.state.get_file(GROUP, "d/p").unwrap(), row_before);

    // The rebootstrap finishes: the deferred work runs.
    unfreeze(&h);
    for _ in 0..4 {
        reconcile(&h, &["d/p"]).await;
    }
    assert_eq!(std::fs::read(h.path("d/p")).unwrap(), b"what the target holds");
}

/// A path that becomes ignored loses its index row at the next full scan, and
/// that is a write of the row: not in a frozen group, whose rows stay until the
/// freeze is over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_newly_ignored_path_keeps_its_index_row_while_frozen() {
    let h = Harness::new(false);
    captured(&h, "d/p", b"captured before it became ignored").await;
    freeze(&h);
    std::fs::write(h.path(".yadorilinkignore"), "d/p\n").unwrap();

    h.scan();

    assert!(h.state.get_file(GROUP, "d/p").unwrap().is_some(), "the frozen row was dropped");

    unfreeze(&h);
    h.scan();
    assert!(h.state.get_file(GROUP, "d/p").unwrap().is_none(), "after the freeze it is dropped");
}

/// The index row of a frozen group cannot be deleted by any caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_index_row_of_a_frozen_group_cannot_be_deleted() {
    let h = Harness::new(false);
    captured(&h, "d/p", b"a row").await;
    freeze(&h);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let rows = h.state.file_index_repository();

    assert!(rows.remove_file(GROUP, "d/p", &permit).is_err());
    assert!(h.state.get_file(GROUP, "d/p").unwrap().is_some());

    unfreeze(&h);
    assert!(rows.remove_file(GROUP, "d/p", &permit).unwrap());
}

/// Evicting in a frozen group is refused before its row is touched: the row is not
/// marked `Evicting` for a lane that is then refused at the fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_eviction_in_a_frozen_group_leaves_its_row_alone() {
    let h = Harness::new(false);
    captured(&h, "d/p", b"hydrated").await;
    let state_of = |h: &Harness| {
        h.state.materialization_state_repository().get_materialization_state(GROUP, "d/p").unwrap()
    };
    let before = state_of(&h);
    freeze(&h);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let opened = h.state.open_eviction(GROUP, "d/p", &permit);

    assert!(opened.is_err() || opened.is_ok_and(|inner| inner.is_err()), "an eviction opened");
    assert_eq!(state_of(&h), before, "the eviction marked a frozen row");
}

/// A sweep that meets a frozen group must not abort on the fence's refusal: it is
/// local to the path, not a failure of the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_refusal_the_sweeps_see_is_local_to_the_path() {
    use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
    let h = Harness::new(false);
    freeze(&h);

    let refused = MaterializationExecutionPort::dag_bump_mutation_fence(
        h.state.as_ref(),
        GROUP,
        "d/p",
        "repair_reconstruct",
    );

    let error = refused.expect_err("a frozen group must refuse the fence");
    assert!(error.is_path_local(), "a frozen group aborts the whole sweep: {error:?}");
}

// --- the final capture pass -----------------------------------------------------------------------

/// The one pause a frozen group has is not the pass's: while a rebootstrap's final capture pass
/// is open the group is not paused for local capture, and the pause is back the moment the pass
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_final_capture_pass_is_not_paused_by_the_freeze() {
    use yadorilink_local_capture::ports::LocalMutationStore;
    let h = Harness::new(false);
    capturing_freeze(&h);
    assert!(h.state.group_frozen(GROUP).unwrap(), "the group is frozen");

    let pass = h.state.begin_capture_pass(GROUP, Arc::new(a_capture_authority(&h)));
    assert!(!h.state.group_frozen(GROUP).unwrap(), "the pass is not paused");

    drop(pass);
    assert!(h.state.group_frozen(GROUP).unwrap(), "the pause is back once the pass ends");
}

/// The pass authors through the freeze under its capability: an edit on disk that no index has
/// seen becomes a delta of the old incarnation while the group is `Capturing`, and an edit made
/// after the pass is not authored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_final_capture_pass_authors_under_its_capability_and_nothing_else_does() {
    let h = Harness::new(false);
    captured(&h, "kept", b"before").await;
    let known = known_deltas(&h);
    capturing_freeze(&h);
    std::fs::write(h.path("unsaved"), b"on disk, in no index").unwrap();

    let pass = h.state.begin_capture_pass(GROUP, Arc::new(a_capture_authority(&h)));
    assert!(matches!(h.capture("unsaved").await, LocalChangeOutcome::FileChanged(_)));
    drop(pass);

    assert_eq!(authored_since(&h, &known), vec!["unsaved".to_string()]);
    std::fs::write(h.path("later"), b"after the pass").unwrap();
    assert!(matches!(h.capture("later").await, LocalChangeOutcome::None), "refused after the pass");
}

const CAPTURING_RECOVERY_ID: &str = "0123456789abcdef0123456789abcdef";

/// The journal of a rebootstrap in `Capturing`: the group is frozen and the one capture pass may
/// run.
fn capturing_freeze(h: &Harness) {
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_rebootstrap::set_journal_for_test(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                "capturing",
                CAPTURING_RECOVERY_ID,
            );
            Ok(())
        })
        .unwrap();
}

fn a_capture_authority(
    h: &Harness,
) -> yadorilink_sync_sqlite::native_rebootstrap::CaptureAuthority {
    let device = h.state.database().read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
        yadorilink_sync_sqlite::author_incarnation::current_author(conn).map(|author| author.device)
    });
    yadorilink_sync_sqlite::native_rebootstrap::CaptureAuthority::for_test(
        &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
        &device.unwrap(),
        CAPTURING_RECOVERY_ID,
    )
}
