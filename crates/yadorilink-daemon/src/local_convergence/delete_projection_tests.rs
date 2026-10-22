#![cfg(test)]
//! Projection of an admitted removal.
//!
//! A delete leaves no head behind, so a path whose admitted state has no
//! present head because an admitted delta removed it is deleted on disk
//! -- but only when the local file is exactly a version the removal
//! superseded (observed by the remover, or absorbed by a change it
//! observed) and nothing on disk is unrecorded. A local edit the remover
//! never saw is never removed: capture records it as a change of its own,
//! whose basis names no current head, so it survives as a head (Q1: a
//! write never supersedes a version its author did not observe).
//!
//! The remote removals here are real signed deltas by another author,
//! admitted through native admission; the projection is the production
//! reconcile pass.

use super::growing_file_projection_tests::{Harness, GROUP};
use super::*;
use crate::test_support::remote_admission_fixture::{admit_remote, delete, put, RemoteOp};
use std::collections::BTreeSet;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::ids::DeltaHash;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::signed_delta::NativeDelta;

const REMOTE_DEVICE: &str = "device-remote";

/// Another author of the group: its deltas are signed with the fixture
/// key of its device and admitted through native admission.
pub(super) struct Remote;

impl Remote {
    pub(super) fn new() -> Self {
        Self
    }

    /// Signs `ops` as this author's next delta and admits it on `h`; its
    /// puts claim a rank above every rank this device's own changes carry.
    pub(super) async fn admit(&mut self, h: &Harness, ops: Vec<RemoteOp>) -> NativeDelta {
        let versions: Vec<_> = ops
            .iter()
            .filter_map(|op| match op {
                RemoteOp::Put { version, .. } => Some(
                    h.state.dag_get_file_version(GROUP, version).unwrap().expect("stored here"),
                ),
                RemoteOp::Delete { .. } => None,
            })
            .collect();
        admit_remote(&h.state, GROUP, REMOTE_DEVICE, ops, &versions)
    }
}

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

pub(super) async fn reconcile(h: &Harness, paths: &[&str]) -> ProjectionAttempt {
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

fn heads(h: &Harness, rel: &str) -> Vec<yadorilink_replica_domain::native_state::LiveHead> {
    h.native_heads(rel)
}

/// Captures `rel` with `bytes` and returns this device's head there.
async fn captured(h: &Harness, rel: &str, bytes: &[u8]) -> DeltaHash {
    if let Some(parent) = h.path(rel).parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(h.path(rel), bytes).unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    DeltaHash(h.own_head(rel).change_hash)
}

/// (1) A removal that observed the version this device holds removes the
/// file, and the path settles as absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_removal_removes_the_file_it_observed() {
    let h = Harness::new(true);
    let seen = captured(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    assert!(heads(&h, "notes.txt").is_empty(), "sanity: a delete leaves no head");

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert!(attempt.is_settled("notes.txt"), "the removal is projected and settles");
    assert!(std::fs::symlink_metadata(h.path("notes.txt")).is_err(), "the file is removed");
    assert!(h.state.get_file(GROUP, "notes.txt").unwrap().is_none_or(|row| row.deleted));
    // Nothing is owed any more: the next pass settles with no work.
    assert!(reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt"));
}

/// A removal of a version that superseded the one this device holds
/// absorbed it: the file this device holds is removed too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_removal_removes_a_version_it_absorbed() {
    let h = Harness::new(true);
    let old = captured(&h, "notes.txt", b"older, held here").await;
    let newer_version = {
        std::fs::write(h.path("scratch.bin"), b"newer, never projected here").unwrap();
        assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
        VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash)
    };
    let mut remote = Remote::new();
    let put = remote.admit(&h, vec![put("notes.txt", newer_version, vec![old])]).await;
    remote.admit(&h, vec![delete("notes.txt", vec![DeltaHash(put.delta_hash().0)])]).await;

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert!(attempt.is_settled("notes.txt"));
    assert!(std::fs::symlink_metadata(h.path("notes.txt")).is_err());
}

/// (2) The file was edited here after this device observed the version the
/// removal saw, and the edit was not captured when the removal arrived --
/// nor by the pass's own pre-delete flush (the harness's flush captures
/// nothing, as for an edit no watcher event has reported yet). The pass
/// never removes it: the disk is not the row's version, so it refuses.
/// Capture then records the edit as a change of its own, which survives as
/// the path's head, and the path settles on the edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_removal_never_removes_an_unobserved_local_edit() {
    let h = Harness::new(false);
    let seen = captured(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    let edited: &[u8] = b"edited here, after the version the remover saw";
    std::fs::write(h.path("notes.txt"), edited).unwrap();

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        edited,
        "a removal must never remove a local edit its author did not observe"
    );
    assert!(!attempt.is_settled("notes.txt"), "the unrecorded edit is not settled as absent");

    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let survivor = h.own_head("notes.txt");
    assert_ne!(survivor.change_hash, seen.0, "the edit is a change of its own");
    let attempt = reconcile(&h, &["notes.txt"]).await;
    assert!(attempt.is_settled("notes.txt"), "the path settles on the edit");
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), edited);
    assert_eq!(heads(&h, "notes.txt").len(), 1, "the edit is the only head");
}

/// (2), with the pass's pre-delete flush reaching capture: the flush
/// records the edit before anything is removed, the path resolves to the
/// edit, and it settles without the file ever leaving the disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unobserved_local_edit_is_captured_by_the_pass_instead_of_removed() {
    let h = Harness::new(true);
    let seen = captured(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    let edited: &[u8] = b"edited here, after the version the remover saw";
    std::fs::write(h.path("notes.txt"), edited).unwrap();

    for _ in 0..3 {
        if reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt") {
            break;
        }
    }

    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), edited);
    let survivor = h.own_head("notes.txt");
    assert_ne!(survivor.change_hash, seen.0, "the edit is a change of its own");
    assert!(reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt"));
}

/// (3) A recursive removal of a tree, one file of which was edited here
/// unobserved: every observed file goes, only the edited one survives, and
/// once captured it is the tree's only head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recursive_removal_keeps_only_the_unobserved_edit_inside() {
    // The pre-delete flush captures nothing: only the disk check stands
    // between the edit and the removal.
    let h = Harness::new(false);
    let a = captured(&h, "tree/a.txt", b"a, seen").await;
    let b = captured(&h, "tree/sub/b.txt", b"b, seen").await;
    let c = captured(&h, "tree/sub/c.txt", b"c, seen").await;
    let mut remote = Remote::new();
    remote
        .admit(
            &h,
            vec![
                delete("tree/a.txt", vec![a]),
                delete("tree/sub/b.txt", vec![b]),
                delete("tree/sub/c.txt", vec![c]),
            ],
        )
        .await;
    let edited: &[u8] = b"b, edited here unobserved";
    std::fs::write(h.path("tree/sub/b.txt"), edited).unwrap();

    let paths = ["tree/a.txt", "tree/sub/b.txt", "tree/sub/c.txt"];
    reconcile(&h, &paths).await;

    assert!(std::fs::symlink_metadata(h.path("tree/a.txt")).is_err());
    assert!(std::fs::symlink_metadata(h.path("tree/sub/c.txt")).is_err());
    assert_eq!(std::fs::read(h.path("tree/sub/b.txt")).unwrap(), edited);

    assert!(matches!(h.capture("tree/sub/b.txt").await, LocalChangeOutcome::FileChanged(_)));
    for _ in 0..3 {
        if reconcile(&h, &paths).await.is_settled("tree/sub/b.txt") {
            break;
        }
    }
    assert_eq!(std::fs::read(h.path("tree/sub/b.txt")).unwrap(), edited);
    assert!(std::fs::symlink_metadata(h.path("tree/a.txt")).is_err());
    assert!(std::fs::symlink_metadata(h.path("tree/sub/c.txt")).is_err());
    assert!(heads(&h, "tree/a.txt").is_empty() && heads(&h, "tree/sub/c.txt").is_empty());
    assert_eq!(heads(&h, "tree/sub/b.txt").len(), 1);
}

/// The same for a symlink retargeted here after the version the removal
/// saw: the link is not removed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_removal_never_removes_an_unobserved_symlink_retarget() {
    let h = Harness::new(false);
    let link = h.path("link");
    std::os::unix::fs::symlink("first-target", &link).unwrap();
    assert!(matches!(h.capture("link").await, LocalChangeOutcome::FileChanged(_)));
    let seen = DeltaHash(h.own_head("link").change_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("link", vec![seen])]).await;
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink("second-target", &link).unwrap();

    let attempt = reconcile(&h, &["link"]).await;

    assert!(!attempt.is_settled("link"));
    assert_eq!(std::fs::read_link(&link).unwrap(), std::path::Path::new("second-target"));
}

/// A file replaced here by a symlink the removal never saw is not unlinked.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_removal_never_removes_an_unobserved_change_of_kind() {
    let h = Harness::new(false);
    let seen = captured(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    std::fs::remove_file(h.path("notes.txt")).unwrap();
    std::os::unix::fs::symlink("elsewhere", h.path("notes.txt")).unwrap();

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert!(!attempt.is_settled("notes.txt"));
    assert_eq!(std::fs::read_link(h.path("notes.txt")).unwrap(), std::path::Path::new("elsewhere"));
}

/// A local chmod the removal never saw is a local change like an edit of
/// the bytes: a version covers the mode, so the file is not unlinked.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_removal_never_removes_an_unobserved_mode_change() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Harness::new(false);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"the version the remover saw").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let seen = DeltaHash(h.own_head("notes.txt").change_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert!(!attempt.is_settled("notes.txt"), "the unrecorded mode change is not settled");
    assert_eq!(std::fs::read(&file).unwrap(), b"the version the remover saw");
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o755);
}

/// The serial (hazard) removal lane resolves the path before it takes the
/// path lock. A change that lands at the path while it waits for the lock
/// makes the path present again; the lane must see that under the lock
/// and not unlink a file whose head is current. The disk still matches
/// the row, so the unrecorded-state guard alone would not stop it, and
/// the colliding sibling is gone by then, so the tombstone's own hazard
/// hold would not either.
///
/// The lane is reached through a case-fold collision with an indexed
/// sibling, so this needs a case-insensitive volume (the macOS default);
/// elsewhere the removal takes the batch lane, which re-resolves too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_serial_removal_lane_re_resolves_under_the_path_lock() {
    let h = Harness::new(false);
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.path("")) {
        return;
    }
    // An indexed sibling that case-folds onto the path, whose own file is
    // gone uncaptured: the removal is a hazard and goes through the serial
    // lane.
    captured(&h, "NOTES.txt", b"an indexed sibling").await;
    std::fs::remove_file(h.path("NOTES.txt")).unwrap();
    let seen = captured(&h, "notes.txt", b"the version the remover saw").await;
    assert!(h.state.get_file(GROUP, "NOTES.txt").unwrap().is_some_and(|row| !row.deleted));
    let newer_version = {
        std::fs::write(h.path("scratch.bin"), b"a newer version landing meanwhile").unwrap();
        assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
        VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash)
    };
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    let synthetic = FileRecord {
        path: "notes.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: true,
    };
    assert!(
        h.convergence.hazard_reason_for_now(GROUP, &synthetic).unwrap().is_some(),
        "sanity: the removal is a hazard"
    );

    let path_lock = h.state.path_lock(GROUP, "notes.txt");
    let guard = path_lock.lock().await;
    let pass = {
        let convergence = h.convergence.clone();
        let driver = driver(&h);
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
                .await
        })
    };
    // Let the pass resolve the path as removed and block on the lock.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // Meanwhile the colliding sibling leaves the index and a newer version
    // lands at the path.
    h.state
        .database()
        .write(|conn| {
            conn.execute(
                "DELETE FROM files WHERE group_id = ?1 AND path = 'NOTES.txt'",
                rusqlite::params![GROUP],
            )
            .map_err(crate::sync_error::SyncError::from)
        })
        .unwrap();
    remote.admit(&h, vec![put("notes.txt", newer_version, Vec::new())]).await;
    drop(guard);
    let attempt = pass.await.unwrap().unwrap().expect("sanity: the pass must actually run");

    assert!(!attempt.is_settled("notes.txt"), "a path present again is retried, not removed");
    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        b"the version the remover saw",
        "a file whose path has a current head is never unlinked"
    );
}

/// The deletion is made durable (parent directory fsync) BEFORE the index
/// records the path as absent: at the moment the parent flush is requested the
/// row must still be live, and the file already unlinked.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_is_durable_before_the_index_records_absence() {
    let h = Harness::new(true);
    let seen = captured(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;

    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (state, observed, path) = (h.state.clone(), observed.clone(), h.path("notes.txt"));
        super::removal_ordering_probe::arm(h.path("notes.txt"), move || {
            let live = state.get_file(GROUP, "notes.txt").unwrap().is_some_and(|row| !row.deleted);
            observed.lock().unwrap().push((live, std::fs::symlink_metadata(&path).is_err()));
        });
    }

    assert!(reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt"));

    assert_eq!(
        *observed.lock().unwrap(),
        vec![(true, true)],
        "the parent flush must run once, after the unlink and while the index still has the row"
    );
    assert!(h.state.get_file(GROUP, "notes.txt").unwrap().is_none_or(|row| row.deleted));
}

/// A metadata step that created the `version_seq = 0` scaffold of a path whose head then went away
/// (the head's content never landed) leaves a row that holds no content and was never authored.
/// Nothing is owed on disk for it, so a pass over the now-empty path retires it and settles,
/// rather than waiting on an authoring identity a scaffold can never have.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scaffold_row_of_a_path_without_a_head_settles_as_absent() {
    let h = Harness::new(true);
    // The group has native history, so an unauthored current row would be refused if it had content.
    captured(&h, "other.txt", b"gives the group a native head").await;
    h.state.file_index_repository().ensure_bootstrap_row_for_metadata(GROUP, "ghost.bin").unwrap();
    assert!(!h.state.has_real_current_row(GROUP, "ghost.bin").unwrap(), "sanity: scaffold only");

    let attempt = reconcile(&h, &["ghost.bin"]).await;

    assert!(attempt.is_settled("ghost.bin"), "a scaffold with no head must not hold the path open");
    assert!(h.state.get_file(GROUP, "ghost.bin").unwrap().is_none_or(|row| row.deleted));
}

/// The scaffold is retired only when nothing is on disk: an object there is local state the
/// removal never observed, and it survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scaffold_row_never_licenses_unlinking_what_is_on_disk() {
    let h = Harness::new(true);
    captured(&h, "other.txt", b"gives the group a native head").await;
    h.state.file_index_repository().ensure_bootstrap_row_for_metadata(GROUP, "ghost.bin").unwrap();
    std::fs::write(h.path("ghost.bin"), b"a local file nobody has captured").unwrap();

    reconcile(&h, &["ghost.bin"]).await;

    assert_eq!(
        std::fs::read(h.path("ghost.bin")).unwrap(),
        b"a local file nobody has captured".to_vec(),
        "the removal must not unlink an unrecorded file"
    );
}

/// A removal is let through a folded sibling only when that sibling is the verified
/// destination of a move of the removed head. A sibling this device created on its own, even
/// with the very bytes of the removed file, is an unrelated create: the removal of the other
/// spelling by a different author stays held (nothing is swept in around it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_is_held_around_an_unrelated_folded_sibling_with_identical_bytes() {
    let h = Harness::new(false);
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.path("")) {
        return;
    }
    captured(&h, "NOTES.txt", b"same bytes").await;
    std::fs::remove_file(h.path("NOTES.txt")).unwrap();
    let seen = captured(&h, "notes.txt", b"same bytes").await;
    assert!(h.state.get_file(GROUP, "NOTES.txt").unwrap().is_some_and(|row| !row.deleted));
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    let synthetic = FileRecord {
        path: "notes.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: true,
    };
    assert!(
        h.convergence.hazard_reason_for_now(GROUP, &synthetic).unwrap().is_some(),
        "an unrelated folded sibling, whatever its bytes, keeps the removal held"
    );
}

/// A path is held while a directory it would be written under (an ancestor, or itself
/// when it is a directory) is on disk under another spelling, and released under that very
/// spelling. Needs a folding volume (the macOS default).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_waits_for_the_old_spelling_of_its_directory_to_go() {
    let h = Harness::new(false);
    if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.path("")) {
        return;
    }
    std::fs::create_dir_all(h.path("Photos/sub")).unwrap();
    let record = |path: &str| FileRecord {
        path: path.into(),
        size: 1,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    for held in ["photos/a.jpg", "photos/sub/b.jpg", "Photos/sub/b.jpg2", "photos", "Photos/SUB"] {
        let reason = h.convergence.hazard_reason_for_now(GROUP, &record(held)).unwrap();
        let expected = held != "Photos/sub/b.jpg2";
        assert_eq!(reason.is_some(), expected, "{held}: {reason:?}");
    }
    for fine in ["Photos/a.jpg", "Photos/sub/b.jpg", "Photos", "Photos/sub", "other/x.jpg"] {
        assert_eq!(
            h.convergence.hazard_reason_for_now(GROUP, &record(fine)).unwrap(),
            None,
            "{fine} is spelled as on disk"
        );
    }
}
