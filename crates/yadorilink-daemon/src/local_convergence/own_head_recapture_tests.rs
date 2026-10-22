#![cfg(test)]
//! An own change derived from local disk capture never writes that disk
//! back.
//!
//! A capture reads a file and signs what it read. Projecting that change
//! later has only one legitimate effect on disk: none. Either the disk
//! still holds what was captured, and the path settles with no write, or
//! the disk moved on, and what moved it is a newer local state that has to
//! be captured -- a newer change -- not overwritten with the older one.
//! The obligation the older change opened then closes because a newer
//! change superseded it, never because its bytes were written back.
//!
//! Changes whose purpose is to change the disk (a restore, a repair
//! carrier) are not capture-derived, and neither is a peer's change: those
//! materialize as they always have.

use super::growing_file_projection_tests::{append, Harness, GROUP, LOCAL_DEVICE};
use super::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::ids::DeltaHash;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::projection_obligations::ProjectionObligation;

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn own_emitter() -> LocalAuthorKey {
    LocalAuthorKey::for_tests(LOCAL_DEVICE, SigningKey::from_bytes(&[7u8; 32]))
}

/// Leaves `path`'s projection owed, the way a capture whose disk
/// observation could not be proven leaves it: the obligation stays open
/// for the Convergence Engine to settle.
fn reopen_obligation(h: &Harness, path: &str) -> ProjectionObligation {
    h.state
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::projection_obligations::bump_projection_obligations_for_touched_paths(
                conn,
                GROUP,
                &[path],
                now_unix_nanos(),
            )
        })
        .unwrap();
    obligation(h, path).expect("sanity: the obligation is open")
}

fn obligation(h: &Harness, path: &str) -> Option<ProjectionObligation> {
    h.state
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::projection_obligations::lookup_projection_obligation(
                conn, GROUP, path,
            )
        })
        .unwrap()
}

/// Overwrites `path` in place with `bytes` of the same length and puts its
/// mtime back: size and mtime both say nothing changed.
fn rewrite_in_place_keeping_size_and_mtime(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write as _;
    let before = std::fs::metadata(path).unwrap();
    assert_eq!(before.len(), bytes.len() as u64, "sanity: the rewrite keeps the size");
    let mtime = before.modified().unwrap();
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.set_modified(mtime).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let after = std::fs::metadata(path).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), mtime, "sanity: the rewrite keeps the mtime");
}

#[cfg(unix)]
fn object_fingerprint(path: &std::path::Path) -> (u64, i64, i64) {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.ino(), meta.ctime(), meta.ctime_nsec())
}

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

async fn reconcile_pass(h: &Harness, path: &str) -> ProjectionAttempt {
    h.convergence
        .reconcile_paths_directly(&driver(h), GROUP, BTreeSet::from([path.to_string()]))
        .await
        .unwrap()
        .expect("sanity: the pass must actually run")
}

/// Whether the current own head's version is exactly what `path` holds.
fn own_head_matches_disk(h: &Harness, rel: &str) -> bool {
    let head = h.own_head(rel);
    let version = h
        .state
        .dag_get_file_version(GROUP, &VersionHash(head.content.as_ref().unwrap().version_hash))
        .unwrap()
        .expect("the head's version is stored");
    let record = file_record_from_version(rel, &version);
    yadorilink_local_storage::disk_bytes_match_indexed_blocks(&h.path(rel), &record.blocks).unwrap()
}

/// The core case. This device captured a file, and its own change is
/// still owed a projection. The file is then rewritten in place -- same
/// size, same mtime, different bytes -- after the pre-write guard looked
/// and before the projection reaches the disk. Projecting the captured
/// change now would put this device's own older view over the newer
/// bytes. It must not write; it must capture what is there now, so the
/// newer local state becomes a newer change, and the older change's
/// obligation closes because it was superseded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_capture_is_recaptured_not_written_back_when_disk_moved_on() {
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured bytes, version one").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("notes.txt");
    let open = reopen_obligation(&h, "notes.txt");

    let edited: &[u8] = b"CAPTURED BYTES, VERSION TWO";
    let target = file.clone();
    *h.after_guard.lock().unwrap() =
        Some(Box::new(move || rewrite_in_place_keeping_size_and_mtime(&target, edited)));

    let result = h.materialize_own_head("notes.txt").await;

    assert_eq!(
        std::fs::read(&file).unwrap(),
        edited,
        "this device's own captured change must never be written over newer local bytes"
    );
    assert!(
        matches!(result, MaterializeResult::RetryRequired),
        "the superseded change is not what disk holds and must not report settled, got \
         {result:?}"
    );
    let newer = h.own_head("notes.txt");
    assert_ne!(
        newer.change_hash, captured.change_hash,
        "the newer local state must be captured as a newer change"
    );
    assert!(own_head_matches_disk(&h, "notes.txt"), "the newer change is what disk holds");
    let after = obligation(&h, "notes.txt");
    assert!(
        after.is_none(),
        "the older change's obligation must close by supersession once the newer state is \
         captured, not stay open to be settled by writing it back: was {open:?}, now {after:?}"
    );

    // What remains owed is nothing: the next pass settles with no write.
    #[cfg(unix)]
    let before = object_fingerprint(&file);
    let attempt = reconcile_pass(&h, "notes.txt").await;
    assert!(attempt.is_settled("notes.txt"), "the newer own change matches disk and settles");
    assert_eq!(std::fs::read(&file).unwrap(), edited);
    #[cfg(unix)]
    assert_eq!(object_fingerprint(&file), before, "settling must not touch the file");
}

/// The same own captured change over a disk that still holds it: settled
/// with zero work, as before -- no rewrite, no new change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_capture_over_unchanged_disk_settles_without_a_write() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured bytes, still on disk").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("notes.txt");
    reopen_obligation(&h, "notes.txt");
    #[cfg(unix)]
    let before = object_fingerprint(&file);

    assert!(
        h.convergence.zero_work_settlement_for_path(GROUP, "notes.txt").unwrap().is_some(),
        "an unchanged captured file is settled by the zero-work close"
    );
    let attempt = reconcile_pass(&h, "notes.txt").await;

    assert!(attempt.is_settled("notes.txt"));
    assert_eq!(std::fs::read(&file).unwrap(), b"captured bytes, still on disk");
    #[cfg(unix)]
    assert_eq!(object_fingerprint(&file), before, "a zero-work settle must not rewrite the file");
    assert_eq!(h.own_head("notes.txt").change_hash, captured.change_hash, "nothing new to author");
}

/// A restore is authored to change the disk: its change names an older
/// version, and disk holds the newer one. It is not a capture of the disk,
/// so the disk not holding it is exactly what it exists to fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_of_an_older_own_version_still_materializes() {
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"the version to restore").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let older = h.own_head("notes.txt");
    let older_version = h
        .state
        .dag_get_file_version(GROUP, &VersionHash(older.content.as_ref().unwrap().version_hash))
        .unwrap()
        .unwrap();
    std::fs::write(&file, b"a later edit that the user restores away").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));

    let operation = yadorilink_replica_domain::session_state::RestoreOperation {
        operation_id: "restore-1".to_string(),
        group_id: GROUP.to_string(),
        path: "notes.txt".to_string(),
        target_version_seq: 1,
        expected_current_version_seq: None,
        state: yadorilink_replica_domain::session_state::RestoreOperationState::Prepared,
        record: file_record_from_version("notes.txt", &older_version),
        origin_device_id: LOCAL_DEVICE.to_string(),
        meta: yadorilink_replica_domain::session_state::LocalFileMetaColumns {
            record_kind: older_version.meta.record_kind,
            symlink_target: older_version.meta.symlink_target.clone(),
            symlink_out_of_root: false,
            unix_mode: older_version.meta.unix_mode,
            xattrs: older_version.meta.xattrs.clone(),
        },
    };
    h.state
        .record_restore_operation_emitting_change(
            &operation,
            &older_version,
            &own_emitter(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(
        h.own_head("notes.txt").content.unwrap().version_hash,
        older_version.version_hash.0,
        "sanity: the restore wins"
    );

    for _ in 0..3 {
        if reconcile_pass(&h, "notes.txt").await.is_settled("notes.txt") {
            break;
        }
    }

    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"the version to restore",
        "a restore's purpose is to change the disk; it must still be written"
    );
}

/// A peer's change over a file this device edited but has not captured
/// is not this device's own change at all: the edit is captured and meets
/// the peer's change as a conflict, and neither side's bytes are lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn winner_arrival_never_overwrites_an_unsynced_local_edit() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured by this device").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    std::fs::write(h.path("peer-content.bin"), b"the peer's newer version").unwrap();
    assert!(matches!(h.capture("peer-content.bin").await, LocalChangeOutcome::FileChanged(_)));
    let peer_version = VersionHash(h.own_head("peer-content.bin").content.unwrap().version_hash);
    let _own = h.own_head("notes.txt");
    crate::test_support::remote_admission_fixture::admit_remote_ops(
        &h.state,
        GROUP,
        "device-remote",
        &[yadorilink_replica_domain::local_op::Op::Put {
            path: yadorilink_replica_domain::ids::SyncPath("notes.txt".into()),
            version: peer_version,
        }],
        crate::test_support::remote_admission_fixture::Basis::CurrentHeads,
    );
    std::fs::write(&file, b"edited here, never captured").unwrap();

    // The pass captures the edit, which meets the peer's change as a contest;
    // the loser's head moves to its copy path, and the pass after writes both.
    for _ in 0..3 {
        reconcile_pass(&h, "notes.txt").await;
        h.fork_own_contests();
    }
    for _ in 0..2 {
        h.convergence
            .reconcile_paths_directly(&driver(&h), GROUP, h.head_paths())
            .await
            .unwrap()
            .expect("sanity: the pass must actually run");
    }

    let mut contents: Vec<Vec<u8>> = std::fs::read_dir(h.path(""))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.is_file() && path.file_name().unwrap().to_string_lossy().starts_with("notes")
        })
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    contents.sort();
    assert!(
        contents.contains(&b"edited here, never captured".to_vec()),
        "the local edit must survive, at the path or as a conflict copy: {contents:?}"
    );
    // Which side wins the path is not fixed. When the peer's version wins, writing it needs the
    // winner to replace the local edit's original, which the closed Windows gate withholds (the
    // edit's copy is made, the original stays); the edit survives either way, checked above.
    if crate::test_support::windows_durability_gate_allows_tests(
        "the peer's winning version replacing the local original",
    ) {
        assert!(
            contents.contains(&b"the peer's newer version".to_vec()),
            "the peer's change must land, at the path or as a conflict copy: {contents:?}"
        );
    }
}

/// The accumulator task is gone while the link is live. A peer's change for
/// a path with an uncaptured local edit must be deferred, with the edit
/// untouched; once an accumulator answers again, the edit is captured and
/// meets the peer's change as a conflict that keeps both sides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_change_is_deferred_while_the_accumulator_is_gone_then_converges() {
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured by this device").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    std::fs::write(h.path("peer-content.bin"), b"the peer's newer version").unwrap();
    assert!(matches!(h.capture("peer-content.bin").await, LocalChangeOutcome::FileChanged(_)));
    let peer_version = VersionHash(h.own_head("peer-content.bin").content.unwrap().version_hash);
    crate::test_support::remote_admission_fixture::admit_remote_ops(
        &h.state,
        GROUP,
        "device-remote",
        &[yadorilink_replica_domain::local_op::Op::Put {
            path: yadorilink_replica_domain::ids::SyncPath("notes.txt".into()),
            version: peer_version,
        }],
        crate::test_support::remote_admission_fixture::Basis::CurrentHeads,
    );
    std::fs::write(&file, b"edited here, never captured").unwrap();
    h.set_accumulator(false);

    let attempt = reconcile_pass(&h, "notes.txt").await;

    assert!(!attempt.is_settled("notes.txt"), "the path must be deferred, not settled");
    assert_eq!(std::fs::read(&file).unwrap(), b"edited here, never captured");

    h.set_accumulator(true);
    for _ in 0..3 {
        reconcile_pass(&h, "notes.txt").await;
        h.fork_own_contests();
    }
    for _ in 0..2 {
        h.convergence
            .reconcile_paths_directly(&driver(&h), GROUP, h.head_paths())
            .await
            .unwrap()
            .expect("sanity: the pass must actually run");
    }
    let contents: Vec<Vec<u8>> = std::fs::read_dir(h.path(""))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.is_file() && path.file_name().unwrap().to_string_lossy().starts_with("notes")
        })
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    assert!(
        contents.contains(&b"edited here, never captured".to_vec()),
        "the local edit must survive: {contents:?}"
    );
    if crate::test_support::windows_durability_gate_allows_tests(
        "the peer's winning version replacing the local original",
    ) {
        assert!(
            contents.contains(&b"the peer's newer version".to_vec()),
            "the peer's change must land, at the path or as a conflict copy: {contents:?}"
        );
    }
}

/// A file that keeps changing is never written over while it does, and
/// the obligation its own captured change left open does not stay open
/// forever: once the file holds still, a capture of it supersedes the
/// older change and the path settles with nothing owed.
///
/// Here the file is already changing when a pass starts, so each pass is
/// deferred by the pre-write guard's own capture, before the recapture
/// rule is reached; the next test drives the rule itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_keeps_changing_leaves_no_open_own_obligation_once_it_settles() {
    let h = Harness::new(true);
    let file = h.path("growing.log");
    std::fs::write(&file, b"first line\n").unwrap();
    assert!(matches!(h.capture("growing.log").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("growing.log");
    reopen_obligation(&h, "growing.log");

    append(&file, b"second line\n");
    let grow = file.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(file.clone(), move || {
        append(&grow, b"more\n");
        true
    });
    for _ in 0..2 {
        let attempt = h
            .convergence
            .reconcile_paths_directly(&driver(&h), GROUP, BTreeSet::from(["growing.log".into()]))
            .await;
        let attempt = attempt.unwrap().expect("sanity: the pass must actually run");
        assert!(!attempt.is_settled("growing.log"), "a file still changing is not settled");
        assert!(
            std::fs::read(&file).unwrap().starts_with(b"first line\nsecond line\nmore\n"),
            "a file still changing must never be written over"
        );
    }
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&file);

    let expected = std::fs::read(&file).unwrap();
    let mut settled = false;
    for _ in 0..3 {
        if reconcile_pass(&h, "growing.log").await.is_settled("growing.log") {
            settled = true;
            break;
        }
    }
    assert_eq!(std::fs::read(&file).unwrap(), expected, "the settled file must be untouched");
    assert!(settled, "once the file holds still the path settles");
    assert_ne!(h.own_head("growing.log").change_hash, captured.change_hash);
    assert!(own_head_matches_disk(&h, "growing.log"), "the settled head is what disk holds");
    assert!(
        obligation(&h, "growing.log").is_none(),
        "no own-head obligation may stay open once a stable capture exists"
    );
}

/// The delta that removed `shown` (the head `rel` held before) from `rel`, which
/// has no head left: a delete leaves none behind. Fails unless a held delta
/// removes exactly that head, landing nothing at `rel`.
fn remover_of(h: &Harness, rel: &str, shown: &PathHead) -> (DeltaHash, String) {
    assert!(h.native_heads(rel).is_empty(), "sanity: no head is left at {rel}");
    let (hash, delta) = h
        .all_deltas()
        .into_iter()
        .find(|(_, delta)| {
            delta.ops.iter().any(|op| {
                op.path.as_str() == rel
                    && op.put.is_none()
                    && op.removes.iter().any(|removal| removal.provenance.0 == shown.change_hash)
            })
        })
        .unwrap_or_else(|| panic!("{rel} has no head but no admitted removal either"));
    (DeltaHash(hash), delta.author.device.0.clone())
}

/// A deletion is a newer local state too. This device captured a file,
/// its own change is still owed a projection, and the user deletes the
/// file before the watcher's event for it is processed. Projecting the
/// captured change would bring the file back. It must not: the deletion
/// is captured instead, as a newer change of this device's own, and the
/// older change's obligation closes because it was superseded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_capture_does_not_bring_back_a_file_deleted_since() {
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured, then deleted by the user").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("notes.txt");
    let open = reopen_obligation(&h, "notes.txt");

    std::fs::remove_file(&file).unwrap();
    let result = h.materialize_own_head("notes.txt").await;

    assert!(
        std::fs::symlink_metadata(&file).is_err(),
        "this device's own captured change must never bring back a file the user deleted"
    );
    assert!(
        matches!(result, MaterializeResult::RetryRequired),
        "the superseded change is not what disk holds, got {result:?}"
    );
    let (remover, device) = remover_of(&h, "notes.txt", &captured);
    assert_ne!(remover.0, captured.change_hash, "the deletion must be captured");
    assert_eq!(device, LOCAL_DEVICE, "the deletion is this device's own change");
    assert_superseded_and_settles(&h, "notes.txt", &open).await;
    assert!(std::fs::symlink_metadata(&file).is_err());
}

/// The older change's obligation is gone or superseded by the newer
/// change's, and what is owed now settles on the next pass.
async fn assert_superseded_and_settles(h: &Harness, rel: &str, open: &ProjectionObligation) {
    if let Some(now) = obligation(h, rel) {
        assert!(
            now.invalidation_generation > open.invalidation_generation,
            "the older change's obligation must be superseded by the newer change: was \
             {open:?}, now {now:?}"
        );
    }
    assert!(reconcile_pass(h, rel).await.is_settled(rel), "what is owed now settles");
}

/// A rename is a deletion at the old name. The file must not end up at
/// both names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_capture_does_not_bring_back_a_file_renamed_away_since() {
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured, then renamed by the user").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("notes.txt");
    let open = reopen_obligation(&h, "notes.txt");

    std::fs::rename(&file, h.path("renamed.txt")).unwrap();
    let _ = h.materialize_own_head("notes.txt").await;

    assert!(
        std::fs::symlink_metadata(&file).is_err(),
        "a file renamed away must not come back at its old name"
    );
    assert_eq!(
        std::fs::read(h.path("renamed.txt")).unwrap(),
        b"captured, then renamed by the user"
    );
    assert_eq!(remover_of(&h, "notes.txt", &captured).1, LOCAL_DEVICE, "the old name is deleted");
    assert_superseded_and_settles(&h, "notes.txt", &open).await;
    assert!(std::fs::symlink_metadata(&file).is_err());
}

/// A symlink this device captured and the user then pointed somewhere
/// else, after the pre-write guard looked: the new target is the newer
/// local state.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_symlink_capture_is_not_written_back_over_a_retargeted_link() {
    let h = Harness::new(true);
    let link = h.path("link");
    std::os::unix::fs::symlink("first-target", &link).unwrap();
    assert!(matches!(h.capture("link").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("link");
    reopen_obligation(&h, "link");

    // After the pre-write guard looked, as in the content case.
    let target = link.clone();
    *h.after_guard.lock().unwrap() = Some(Box::new(move || {
        std::fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink("second-target", &target).unwrap();
    }));
    let _ = h.materialize_own_head("link").await;

    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        std::path::Path::new("second-target"),
        "this device's own captured link must never be written over a newer target"
    );
    let newer = h.own_head("link");
    assert_ne!(newer.change_hash, captured.change_hash, "the new target must be captured");
    assert!(obligation(&h, "link").is_none());
}

/// Capture compares the disk with the index row, not with the head. When
/// the two disagree -- the row names other bytes than this device's own
/// captured head, and disk holds the row's -- the recapture finds nothing
/// newer to author. That is not a reason to retry forever: capture has
/// just said there is no uncaptured local state at the path, so the path
/// is projected as it was before the recapture rule existed, and settles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recapture_that_finds_nothing_newer_does_not_leave_the_path_retrying() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured as the head").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("notes.txt");
    reopen_obligation(&h, "notes.txt");

    // The row (and disk) name other bytes than the head does.
    std::fs::write(h.path("scratch.bin"), b"what the row says").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let mut row = h.state.get_file(GROUP, "scratch.bin").unwrap().unwrap();
    row.path = "notes.txt".to_string();
    h.state
        .upsert_file_with_origin(GROUP, &row, LOCAL_DEVICE, &RootCommitPermit::for_tests())
        .unwrap();
    std::fs::write(&file, b"what the row says").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(
            std::time::UNIX_EPOCH + std::time::Duration::from_nanos(row.mtime_unix_nanos as u64),
        )
        .unwrap();
    assert!(
        matches!(h.capture("notes.txt").await, LocalChangeOutcome::None),
        "sanity: capture finds disk equal to the row"
    );

    // Projecting the head over the row's bytes replaces the file, which needs
    // durable namespace changes.
    if !crate::test_support::windows_durability_gate_allows_tests("the head replacing the file") {
        return;
    }
    let mut settled = false;
    for _ in 0..3 {
        if reconcile_pass(&h, "notes.txt").await.is_settled("notes.txt") {
            settled = true;
            break;
        }
    }
    assert!(settled, "a recapture that authored nothing must not leave the path retrying");
    assert_eq!(h.own_head("notes.txt").change_hash, captured.change_hash, "nothing was captured");
}

/// A mode change is a local edit capture records as one. This device's own
/// captured change still owed a projection, with the file made executable
/// after the pre-write guard looked: the bytes still match, so the
/// projection used to "repair" the metadata back to the captured mode.
/// The newer mode must be captured instead.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_capture_does_not_revert_a_mode_change_made_since() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Harness::new(true);
    let file = h.path("run.sh");
    std::fs::write(&file, b"#!/bin/sh\necho captured\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(h.capture("run.sh").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("run.sh");
    let open = reopen_obligation(&h, "run.sh");

    let target = file.clone();
    *h.after_guard.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    }));
    let _ = h.materialize_own_head("run.sh").await;

    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o755,
        "this device's own captured change must never revert a newer local mode"
    );
    assert_ne!(h.own_head("run.sh").change_hash, captured.change_hash, "the new mode is captured");
    assert_superseded_and_settles(&h, "run.sh", &open).await;
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o755);
}

/// An mtime-only change (`touch`) is not an edit capture records, but it
/// is not this device's own captured change's to undo either: the path
/// settles without stamping the captured mtime back over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_capture_does_not_stamp_its_mtime_over_a_touch_made_since() {
    let h = Harness::new(true);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"captured, then touched").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    reopen_obligation(&h, "notes.txt");

    let touched = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    let target = file.clone();
    *h.after_guard.lock().unwrap() = Some(Box::new(move || {
        std::fs::File::options().write(true).open(&target).unwrap().set_modified(touched).unwrap();
    }));
    let result = h.materialize_own_head("notes.txt").await;

    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        touched,
        "this device's own captured change must not stamp its mtime over a newer one"
    );
    assert!(
        matches!(result, MaterializeResult::Settled(_)),
        "the captured content is what disk holds, got {result:?}"
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"captured, then touched");
}

/// The recapture rule's own liveness. The file changes after the pre-write
/// guard looked, and keeps changing while the recapture reads it: the
/// recapture cannot capture it yet, and nothing is written over it. Once it
/// holds still, a later pass captures it, the newer change supersedes the
/// older one, and the path settles with nothing owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_still_changing_during_its_recapture_is_captured_once_it_holds_still() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let h = Harness::new(true);
    let file = h.path("growing.log");
    std::fs::write(&file, b"first line\n").unwrap();
    assert!(matches!(h.capture("growing.log").await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head("growing.log");
    let open = reopen_obligation(&h, "growing.log");

    // Two reads race a write: the recapture's, and the next pass's guard.
    let raced = Arc::new(AtomicUsize::new(0));
    let (target, counter) = (file.clone(), raced.clone());
    *h.after_guard.lock().unwrap() = Some(Box::new(move || {
        append(&target, b"second line\n");
        let grow = target.clone();
        yadorilink_local_capture::test_hooks::arm_content_read_race_hook(
            target.clone(),
            move || {
                append(&grow, b"more\n");
                counter.fetch_add(1, Ordering::SeqCst) + 1 < 2
            },
        );
    }));

    let result = h.materialize_own_head("growing.log").await;

    assert_eq!(
        raced.load(Ordering::SeqCst),
        1,
        "the recapture must try to capture the newer bytes on this pass"
    );
    assert!(matches!(result, MaterializeResult::RetryRequired), "got {result:?}");
    assert!(
        std::fs::read(&file).unwrap().starts_with(b"first line\nsecond line\nmore\n"),
        "a file still changing must never be written over"
    );
    assert_eq!(h.own_head("growing.log").change_hash, captured.change_hash, "nothing captured yet");
    assert_eq!(
        obligation(&h, "growing.log").map(|o| o.invalidation_generation),
        Some(open.invalidation_generation),
        "the older change's obligation stays owed while nothing supersedes it"
    );

    let mut settled = false;
    for _ in 0..3 {
        if reconcile_pass(&h, "growing.log").await.is_settled("growing.log") {
            settled = true;
            break;
        }
    }
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&file);
    assert!(settled, "once the file holds still the path settles");
    assert_eq!(raced.load(Ordering::SeqCst), 2, "sanity: the file stopped changing");
    assert_ne!(h.own_head("growing.log").change_hash, captured.change_hash);
    assert!(own_head_matches_disk(&h, "growing.log"), "the settled head is what disk holds");
    assert!(
        std::fs::read(&file).unwrap().ends_with(b"more\nmore\n"),
        "the settled file must be untouched"
    );
    if let Some(now) = obligation(&h, "growing.log") {
        assert!(now.invalidation_generation > open.invalidation_generation);
    }
}

/// `materialize_own_head`, but handing back the error a failed pass returns.
async fn try_materialize_own_head(
    h: &Harness,
    rel: &str,
) -> Result<MaterializeResult, PeerSessionError> {
    let node = h
        .state
        .native_plan_level(GROUP, super::namespace_steps::parent_of(rel))
        .unwrap()
        .nodes
        .get(&yadorilink_replica_domain::ids::SyncPath(rel.to_owned()))
        .cloned()
        .unwrap_or_else(|| panic!("the plan places an entry at {rel}"));
    h.convergence
        .materialize_native_entry(
            GROUP,
            rel,
            &node,
            yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
            None,
            None,
        )
        .await
}

/// The evidence that a vanished file was once here is the row's `Present`
/// materialization state. When that cannot be read, nothing proves the
/// absence is not the user's delete, so the pass stops: it neither writes the
/// old head back nor captures anything, and the next pass, once the read
/// works, treats the absence as the deletion it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_materialization_state_never_brings_back_a_deleted_file() {
    let rel = "unreadable-state-166.txt";
    let h = Harness::new(true);
    let file = h.path(rel);
    std::fs::write(&file, b"captured, then deleted by the user").unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    let captured = h.own_head(rel);
    let open = reopen_obligation(&h, rel);
    std::fs::remove_file(&file).unwrap();

    yadorilink_sync_sqlite::fail_state_reads_for_path(rel, true);
    let failed = try_materialize_own_head(&h, rel).await;
    yadorilink_sync_sqlite::fail_state_reads_for_path(rel, false);

    assert!(failed.is_err(), "an unreadable state must stop the pass, got {failed:?}");
    assert!(
        std::fs::symlink_metadata(&file).is_err(),
        "the old head must not be written back over the user's delete"
    );
    assert_eq!(h.own_head(rel).change_hash, captured.change_hash, "nothing was authored either");

    // The read works again: the same absence is now the deletion it is.
    let retry = try_materialize_own_head(&h, rel).await.unwrap();
    assert!(matches!(retry, MaterializeResult::RetryRequired), "got {retry:?}");
    let (remover, device) = remover_of(&h, rel, &captured);
    assert_ne!(remover.0, captured.change_hash, "the deletion must be captured");
    assert_eq!(device, LOCAL_DEVICE);
    assert_superseded_and_settles(&h, rel, &open).await;
    assert!(std::fs::symlink_metadata(&file).is_err());
}

/// A state that is readable and says the file was never hydrated keeps its
/// existing handling: nothing proves a file was here, so the projection is not
/// blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_definitely_not_present_row_still_projects_over_an_absent_path() {
    let rel = "remote-state-166.txt";
    let h = Harness::new(true);
    let file = h.path(rel);
    std::fs::write(&file, b"captured, never hydrated").unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    h.state
        .database()
        .write(|conn| {
            conn.execute(
                "UPDATE files SET materialization_state = 'remote' WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, rel],
            )?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
    std::fs::remove_file(&file).unwrap();

    let result = try_materialize_own_head(&h, rel).await.expect("a readable state does not fail");

    assert!(!matches!(result, MaterializeResult::RetryRequired), "got {result:?}");
}

/// A path that cannot be examined at all (an interior NUL is refused by every
/// platform with an error that is not "not found") is not an absent path:
/// both guards must fail rather than conclude there is nothing to protect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stat_error_other_than_absence_stops_the_write_and_removal_guards() {
    let rel = "stat-error-189.txt";
    let h = Harness::new(true);
    std::fs::write(h.path(rel), b"user bytes").unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    let unexaminable = h.path("bad\0name.txt");

    let write_guard =
        h.convergence.disk_holds_uncaptured_local_bytes(GROUP, rel, &unexaminable, None);
    let removal_guard =
        h.convergence.removal_would_destroy_unrecorded_state(GROUP, rel, &unexaminable);

    assert!(write_guard.is_err(), "got {write_guard:?}");
    assert!(removal_guard.is_err(), "got {removal_guard:?}");
    // A genuinely absent path is still nothing to protect.
    let absent = h.path("never-here-189.txt");
    assert!(!h.convergence.disk_holds_uncaptured_local_bytes(GROUP, rel, &absent, None).unwrap());
}

#[cfg(windows)]
mod remote_row_guards {
    use super::*;

    /// A `Remote` row for `rel` whose path holds `user_bytes` the row does not
    /// describe, with the given recorded placeholder generation (`None` =
    /// none recorded).
    async fn remote_row_over_user_bytes(
        h: &Harness,
        rel: &str,
        generation: Option<(i64, i64, &str)>,
    ) -> std::path::PathBuf {
        let file = h.path(rel);
        std::fs::write(&file, b"captured by the device").unwrap();
        assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
        h.state
            .database()
            .write(|conn| {
                conn.execute(
                    "UPDATE files SET materialization_state = 'remote', placeholder_dev = ?3, \
                     placeholder_ino = ?4, placeholder_provider_kind = ?5 \
                     WHERE group_id = ?1 AND path = ?2",
                    rusqlite::params![
                        GROUP,
                        rel,
                        generation.map(|g| g.0),
                        generation.map(|g| g.1),
                        generation.map(|g| g.2),
                    ],
                )?;
                Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
            })
            .unwrap();
        std::fs::write(&file, b"bytes the user wrote after, not recorded anywhere").unwrap();
        file
    }

    /// Every path that asks "is this an untouched placeholder" fails closed
    /// when the generation cannot be read: the write guard (local edit
    /// check), the removal guard, and the own-capture check behind a
    /// projection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_placeholder_generation_stops_all_three_paths() {
        let rel = "unreadable-generation-189.txt";
        let h = Harness::new(false);
        let file = remote_row_over_user_bytes(&h, rel, None).await;

        yadorilink_sync_sqlite::fail_placeholder_reads_for_path(rel, true);
        let write_guard = h.convergence.disk_holds_uncaptured_local_bytes(GROUP, rel, &file, None);
        let removal_guard = h.convergence.removal_would_destroy_unrecorded_state(GROUP, rel, &file);
        let projection = try_materialize_own_head(&h, rel).await;
        yadorilink_sync_sqlite::fail_placeholder_reads_for_path(rel, false);

        assert!(write_guard.is_err(), "write guard: {write_guard:?}");
        assert!(removal_guard.is_err(), "removal guard: {removal_guard:?}");
        assert!(projection.is_err(), "projection: {projection:?}");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"bytes the user wrote after, not recorded anywhere",
            "nothing was written over the user's bytes"
        );
    }

    /// No recorded generation, or another provider's, is not a confirmation
    /// that this device wrote the object: the user's bytes are protected by
    /// every path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_missing_or_foreign_generation_never_vouches_for_user_bytes() {
        for (rel, generation) in [
            ("missing-generation-189.txt", None),
            ("foreign-generation-189.txt", Some((1_i64, 2_i64, "another-provider"))),
        ] {
            let h = Harness::new(false);
            let file = remote_row_over_user_bytes(&h, rel, generation).await;

            assert!(
                h.convergence.disk_holds_uncaptured_local_bytes(GROUP, rel, &file, None).unwrap(),
                "{rel}: write guard"
            );
            assert!(
                h.convergence.removal_would_destroy_unrecorded_state(GROUP, rel, &file).unwrap(),
                "{rel}: removal guard"
            );
            let _ = try_materialize_own_head(&h, rel).await.unwrap();
            assert_eq!(
                std::fs::read(&file).unwrap(),
                b"bytes the user wrote after, not recorded anywhere",
                "{rel}: nothing was written over the user's bytes"
            );
        }
    }
}
