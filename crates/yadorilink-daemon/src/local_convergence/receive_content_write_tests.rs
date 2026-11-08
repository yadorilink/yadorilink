//! A peer's file content written here end to end: an empty file, a file of
//! one block and a file of several, each proven exactly once its bytes are
//! durable; and a write whose path is touched after its pre-write commit,
//! which must publish nothing.

use std::collections::BTreeSet;
use std::sync::Arc;

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;

use super::growing_file_projection_tests::{Harness, GROUP};
use crate::test_support::remote_admission_fixture::{admit_remote, put};

/// Captures `content` under a scratch name and admits a peer's put of that
/// same version at `name`, so the blocks are this group's and `name` has no
/// row yet: what a fresh receive looks like once its fetch is done.
async fn admit_received(h: &Harness, name: &str, content: &[u8]) -> FileVersion {
    let source = format!("source-{name}");
    std::fs::write(h.path(&source), content).unwrap();
    assert!(matches!(h.capture(&source).await, LocalChangeOutcome::FileChanged(_)));
    let version = VersionHash(h.own_head(&source).content.unwrap().version_hash);
    let stored = h.state.dag_get_file_version(GROUP, &version).unwrap().expect("stored here");
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put(name, version, vec![])],
        std::slice::from_ref(&stored),
    );
    stored
}

async fn project(h: &Harness, name: &str) {
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from([name.to_owned()]))
        .await;
}

/// The version the published proof at `name` names, if one is current.
fn proven_version(h: &Harness, name: &str) -> Option<VersionHash> {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                conn, GROUP, name,
            )
        })
        .unwrap()
        .and_then(|basis| basis.version)
}

async fn receive_and_prove(content: &[u8], expect_blocks: std::ops::RangeInclusive<usize>) {
    let h = Harness::new(false);
    let version = admit_received(&h, "received.bin", content).await;
    assert!(
        expect_blocks.contains(&version.blocks.len()),
        "fixture: {} blocks",
        version.blocks.len()
    );

    project(&h, "received.bin").await;

    assert_eq!(std::fs::read(h.path("received.bin")).unwrap(), content, "exact bytes on disk");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "received.bin").unwrap(),
        Some(MaterializationState::Present)
    );
    assert_eq!(proven_version(&h, "received.bin"), Some(version.version_hash), "exact proof");
    assert!(
        !h.state.has_materialization_intent(GROUP, "received.bin").unwrap(),
        "the proof's commit clears the intent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_file_is_received_and_proven() {
    receive_and_prove(b"", 0..=0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_block_file_is_received_and_proven() {
    receive_and_prove(b"one small block of a peer's file", 1..=1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_block_file_is_received_and_proven() {
    let block = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
    let content: Vec<u8> = (0..2 * block + 1000).map(|i| (i % 251) as u8).collect();
    receive_and_prove(&content, 2..=usize::MAX).await;
}

/// What a write touched after its pre-write commit leaves: no proof, the
/// row still in flight, the intent still open, so a later pass re-drives it.
fn assert_published_nothing(h: &Harness, name: &str, context: &str) {
    assert_eq!(proven_version(h, name), None, "{context}: no proof is published");
    assert_ne!(
        h.state.get_materialization_state(GROUP, name).unwrap(),
        Some(MaterializationState::Present),
        "{context}: the row does not claim the bytes"
    );
    assert!(
        h.state.has_materialization_intent(GROUP, name).unwrap(),
        "{context}: the intent stays open, so the write is re-driven"
    );
}

/// A capture or any other mutator of the path bumps its fence after the
/// write's pre-write commit and before its proof: the proof's CAS is on the
/// value that commit bumped, so it must fail. The bytes on disk at that
/// moment may already be someone else's to describe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fence_moved_after_the_pre_write_commit_makes_the_proof_publish_nothing() {
    let h = Harness::new(false);
    let content = b"bytes whose proof loses its fence";
    admit_received(&h, "raced.bin", content).await;
    let state = h.state.clone();
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        state.dag_bump_mutation_fence(GROUP, "raced.bin", "local_capture").unwrap();
    }));

    project(&h, "raced.bin").await;

    assert_published_nothing(&h, "raced.bin", "fence moved");
}

/// A local save lands on the path after the pre-write commit and before the
/// rename: it is kept, and nothing is proven for the peer's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_edit_after_the_pre_write_commit_is_kept_and_publishes_nothing() {
    let h = Harness::new(false);
    admit_received(&h, "edited.bin", b"the peer's bytes").await;
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"saved locally meanwhile").unwrap()));

    project(&h, "edited.bin").await;

    assert_eq!(std::fs::read(h.path("edited.bin")).unwrap(), b"saved locally meanwhile");
    assert_published_nothing(&h, "edited.bin", "local edit");
}

/// A save lands after the pre-publish check, in the instant before the replacement: nothing stood
/// at the name, and the save is kept, not replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_after_the_pre_publish_check_is_kept_over_a_missing_name() {
    let h = Harness::new(false);
    admit_received(&h, "late.bin", b"the peer's bytes").await;
    *h.convergence.after_check_before_publish_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"saved at the last moment").unwrap()));

    project(&h, "late.bin").await;

    assert_eq!(std::fs::read(h.path("late.bin")).unwrap(), b"saved at the last moment");
    assert_published_nothing(&h, "late.bin", "late save");
    assert!(h.state.is_path_dirty(GROUP, "late.bin").unwrap(), "the save is journaled");
}

/// The same over an existing file: an in-place edit of the file the write was based on, made
/// after the pre-publish check, is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_after_the_pre_publish_check_is_kept_over_an_existing_file() {
    let h = Harness::new(false);
    std::fs::write(h.path("scratch.bin"), b"the peer's v2 bytes").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let v2 = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let stored = h.state.dag_get_file_version(GROUP, &v2).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), b"captured v1 bytes").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    crate::test_support::remote_admission_fixture::admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", v2, vec![own])],
        &[stored],
    );
    *h.convergence.after_check_before_publish_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"edited after the check").unwrap()));

    project(&h, "notes.txt").await;

    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"edited after the check");
}

/// On a volume that cannot answer the change time / USN (simulated through the
/// fingerprint seam; a no-op on macOS, where the stat fingerprint itself shows
/// the rewrite), a same-size rewrite that restores the mtime lands during the
/// assembly with the watcher not having journaled it. The fingerprint and the
/// dirty journal both pass, so only the bytes can refuse the rename. Only Windows reaches that
/// byte comparison (stat-only is never true elsewhere, and the Unix fingerprint carries ctime, which
/// rejects the rewrite first), so the new check is exercised only there. The seam is thread-local:
/// keep this test current-thread.
#[tokio::test(flavor = "current_thread")]
async fn a_same_size_mtime_restoring_rewrite_during_assembly_is_kept_when_the_change_time_is_unreadable(
) {
    let _unreadable = yadorilink_fs_platform::fs_identity::change_time_unreadable_for_test();
    let h = Harness::new(false);
    std::fs::write(h.path("scratch.bin"), b"the peer's v2 bytes").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let v2 = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let stored = h.state.dag_get_file_version(GROUP, &v2).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), b"captured v1 bytes").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    crate::test_support::remote_admission_fixture::admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", v2, vec![own])],
        &[stored],
    );
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(|out_path| {
        let mtime = std::fs::metadata(out_path).unwrap().modified().unwrap();
        std::fs::write(out_path, b"user edit same ln").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(out_path).unwrap();
        file.set_modified(mtime).unwrap();
    }));

    project(&h, "notes.txt").await;

    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        b"user edit same ln",
        "the rewrite must survive: the bytes differ from the indexed content"
    );
}

/// The volume under the link root disappears while a peer's content is being
/// assembled (the marker goes with it, the mountpoint stays). The rename
/// must not land on the bare mountpoint, and no proof or Present row is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_root_that_leaves_its_volume_before_the_rename_receives_nothing() {
    let h = Harness::new(false);
    admit_received(&h, "unmounted.bin", b"bytes for a vanished volume").await;
    let marker = h.path(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME);
    assert!(marker.exists(), "fixture: the root carries its marker");
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(move |_| std::fs::remove_file(&marker).unwrap()));

    project(&h, "unmounted.bin").await;

    assert!(on_disk(&h, "unmounted.bin").is_none(), "nothing written to the parent filesystem");
    assert_published_nothing(&h, "unmounted.bin", "root off its volume");
}

fn on_disk(h: &Harness, name: &str) -> Option<Vec<u8>> {
    std::fs::read(h.path(name)).ok()
}

/// A peer's change that arrives while the link's startup (initial scan and
/// dirty-journal redrive) has not captured local state is deferred, not
/// written: an offline local delete or edit is otherwise indistinguishable
/// from an absent path. It applies once startup settles successfully.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_change_before_startup_has_captured_is_deferred_then_applied() {
    let h = Harness::new(false);
    let generation = h.state.startup_readiness().begin_group_startup(GROUP);
    admit_received(&h, "early.bin", b"arrived before the scan finished").await;

    project(&h, "early.bin").await;
    assert!(on_disk(&h, "early.bin").is_none(), "deferred while startup is running");

    h.state.startup_readiness().mark_group_ready(GROUP, generation);
    project(&h, "early.bin").await;
    assert_eq!(
        std::fs::read(h.path("early.bin")).unwrap(),
        b"arrived before the scan finished",
        "applied after capture"
    );
}

/// A failed startup defers peer apply without parking it, and the next
/// startup attempt that succeeds releases it. Nothing waits on the gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_startup_defers_without_blocking_and_a_later_success_releases() {
    let h = Harness::new(false);
    let failed = h.state.startup_readiness().begin_group_startup(GROUP);
    h.state.startup_readiness().mark_group_failed(GROUP, failed, "scan failed");
    admit_received(&h, "late.bin", b"deferred by a failed startup").await;

    tokio::time::timeout(std::time::Duration::from_secs(10), project(&h, "late.bin"))
        .await
        .expect("a failed gate must defer, not park");
    assert!(on_disk(&h, "late.bin").is_none());

    let retry = h.state.startup_readiness().begin_group_startup(GROUP);
    h.state.startup_readiness().mark_group_ready(GROUP, retry);
    project(&h, "late.bin").await;
    assert!(on_disk(&h, "late.bin").is_some(), "released by the successful retry");
}

/// One group's startup never holds another, idle or ready, group back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_groups_running_startup_does_not_hold_a_ready_group() {
    let h = Harness::new(false);
    let _other = h.state.startup_readiness().begin_group_startup("some-other-group");
    admit_received(&h, "ready.bin", b"unaffected").await;

    project(&h, "ready.bin").await;
    assert!(on_disk(&h, "ready.bin").is_some());
}

/// A user save landing after the daemon's write and before the proof
/// observes the object must not be read as the daemon's own write: nothing
/// is proven, the path is dirty, the user's bytes survive, and capture
/// authors them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_user_edit_between_the_write_and_its_proof_is_captured_not_absorbed() {
    let h = Harness::new(false);
    admit_received(&h, "absorbed.bin", b"the peer's bytes").await;
    *h.convergence.after_write_before_proof_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"user edit right after").unwrap()));

    project(&h, "absorbed.bin").await;

    assert_eq!(std::fs::read(h.path("absorbed.bin")).unwrap(), b"user edit right after");
    assert_eq!(proven_version(&h, "absorbed.bin"), None, "no proof for bytes that were replaced");
    assert!(h.state.is_path_dirty(GROUP, "absorbed.bin").unwrap(), "the edit is journaled");

    assert!(matches!(h.capture("absorbed.bin").await, LocalChangeOutcome::FileChanged(_)));
    assert_eq!(std::fs::read(h.path("absorbed.bin")).unwrap(), b"user edit right after");
}

/// A `chmod` landing after the daemon's write and before the proof observes the object is a
/// local edit, not the daemon's own flag: nothing is proven, the path is dirty, and capture
/// authors the new execute flag.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chmod_between_the_write_and_its_proof_is_captured_not_absorbed() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(false);
    admit_received(&h, "mode.sh", b"#!/bin/sh\n").await;
    *h.convergence.after_write_before_proof_hook.lock().unwrap() = Some(Box::new(|out_path| {
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }));

    project(&h, "mode.sh").await;

    assert_eq!(proven_version(&h, "mode.sh"), None, "no proof for a flag that was changed");
    assert!(h.state.is_path_dirty(GROUP, "mode.sh").unwrap(), "the chmod is journaled");
    assert!(matches!(h.capture("mode.sh").await, LocalChangeOutcome::FileChanged(_)));
    let mode = std::fs::metadata(h.path("mode.sh")).unwrap().permissions().mode();
    assert_eq!(mode & 0o100, 0o100, "the user's flag survives");
}

/// The user deletes the file after the daemon's write and before the proof
/// observes it. The write completed, so it is closed (the row settles
/// `Present` with a proof and no open intent) and the delete is indexed
/// natively, not dropped as the daemon's own removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_user_delete_between_the_write_and_its_proof_is_closed_and_indexed() {
    let h = Harness::new(false);
    admit_received(&h, "gone.bin", b"the peer's bytes").await;
    *h.convergence.after_write_before_proof_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::remove_file(out_path).unwrap()));

    project(&h, "gone.bin").await;

    assert!(on_disk(&h, "gone.bin").is_none());
    assert!(!h.state.has_materialization_intent(GROUP, "gone.bin").unwrap(), "the write closed");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "gone.bin").unwrap(),
        Some(MaterializationState::Present)
    );
    assert!(matches!(h.observe_removal("gone.bin").await, LocalChangeOutcome::FileChanged(_)));
    assert!(h.state.get_file(GROUP, "gone.bin").unwrap().is_some_and(|row| row.deleted));
    assert!(h.native_heads("gone.bin").is_empty(), "the delete must reach the native state");
}

/// A write whose "landed" mark cannot be recorded does not settle: the bytes are in place under
/// an intent that does not say so, so the path stays unsettled (no proof, intent open) for the
/// next pass instead of being logged past.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_landed_mark_that_cannot_be_recorded_leaves_the_write_unsettled() {
    let h = Harness::new(false);
    admit_received(&h, "unmarked.bin", b"the peer's bytes").await;
    h.state
        .database()
        .write(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER refuse_landed_mark BEFORE UPDATE OF mutation_generation ON materialization_intents \
         WHEN OLD.mutation_generation IS NULL AND NEW.mutation_generation IS NOT NULL \
         BEGIN SELECT RAISE(ABORT, 'landed mark refused'); END;",
            )?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();

    project(&h, "unmarked.bin").await;

    assert_published_nothing(&h, "unmarked.bin", "the mark was refused");
}

/// The untouched path still gets its proof, with no dirty churn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untouched_write_is_still_proven_and_not_dirty() {
    let h = Harness::new(false);
    let version = admit_received(&h, "clean.bin", b"nobody touches this").await;

    project(&h, "clean.bin").await;

    assert_eq!(proven_version(&h, "clean.bin"), Some(version.version_hash));
    assert!(!h.state.is_path_dirty(GROUP, "clean.bin").unwrap());
    assert!(!h.state.has_materialization_intent(GROUP, "clean.bin").unwrap());
}

// The order of a write's durable steps, as the write operation records it.
// These pin the order the eager lane has always had (open the write, place the
// bytes, prove them in one commit) so a change to the lane's structure that
// reorders it shows up here.

use crate::write_op::trace::StepTrace;
use crate::write_op::{IntentSettlement, ProofOutcome, StepEvent};

const PREPARED_PUBLISHED_PROVEN: [StepEvent; 3] = [
    StepEvent::Prepared,
    StepEvent::Published { names_deferred: false, landed_marked: true },
    StepEvent::Proven {
        outcome: ProofOutcome::Exact,
        intent: IntentSettlement::Cleared,
        obligation_closed: false,
    },
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_file_goes_prepared_published_proven() {
    let h = Harness::new(false);
    admit_received(&h, "trace-new.bin", b"a file this device has never held").await;

    project(&h, "trace-new.bin").await;

    assert_eq!(StepTrace::of(GROUP, "trace-new.bin"), PREPARED_PUBLISHED_PROVEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_file_goes_prepared_published_proven() {
    let h = Harness::new(false);
    admit_received(&h, "trace-empty.bin", b"").await;

    project(&h, "trace-empty.bin").await;

    assert_eq!(StepTrace::of(GROUP, "trace-empty.bin"), PREPARED_PUBLISHED_PROVEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacing_write_goes_prepared_published_proven() {
    let h = Harness::new(false);
    std::fs::write(h.path("trace-new-bytes.bin"), b"the peer's newer bytes").unwrap();
    assert!(matches!(h.capture("trace-new-bytes.bin").await, LocalChangeOutcome::FileChanged(_)));
    let v2 = VersionHash(h.own_head("trace-new-bytes.bin").content.unwrap().version_hash);
    let stored = h.state.dag_get_file_version(GROUP, &v2).unwrap().expect("stored");
    std::fs::write(h.path("trace-replaced.txt"), b"captured older bytes").unwrap();
    assert!(matches!(h.capture("trace-replaced.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own =
        yadorilink_replica_domain::ids::DeltaHash(h.own_head("trace-replaced.txt").change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("trace-replaced.txt", v2, vec![own])],
        &[stored],
    );

    project(&h, "trace-replaced.txt").await;

    assert_eq!(std::fs::read(h.path("trace-replaced.txt")).unwrap(), b"the peer's newer bytes");
    assert_eq!(StepTrace::of(GROUP, "trace-replaced.txt"), PREPARED_PUBLISHED_PROVEN);
}

/// A write that loses the target to a local save is opened and never published.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_that_meets_a_local_edit_stops_after_prepared() {
    let h = Harness::new(false);
    admit_received(&h, "trace-edited.bin", b"the peer's bytes").await;
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"saved locally meanwhile").unwrap()));

    project(&h, "trace-edited.bin").await;

    assert_eq!(StepTrace::of(GROUP, "trace-edited.bin"), [StepEvent::Prepared]);
}

/// A proof that loses its fence is published and never proven.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_that_loses_its_fence_stops_after_published() {
    let h = Harness::new(false);
    admit_received(&h, "trace-raced.bin", b"bytes whose proof loses its fence").await;
    let state = h.state.clone();
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        state.dag_bump_mutation_fence(GROUP, "trace-raced.bin", "local_capture").unwrap();
    }));

    project(&h, "trace-raced.bin").await;

    assert_eq!(
        StepTrace::of(GROUP, "trace-raced.bin"),
        [StepEvent::Prepared, PREPARED_PUBLISHED_PROVEN[1]]
    );
    // The fence moved before the rename, so the landed mark is refused: the intent stays
    // `prepared` and the re-driven write decides.
    #[cfg(unix)]
    assert_eq!(
        super::receive_deferred_flush_tests::intent_phase(&h, "trace-raced.bin").as_deref(),
        Some("prepared")
    );
}

/// The watcher journals the path as dirty while the bytes are assembled, though
/// nothing the stat fingerprint covers has moved yet: that alone refuses the rename.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_journaled_dirty_during_assembly_is_not_renamed_over() {
    let h = Harness::new(false);
    admit_received(&h, "dirtied.bin", b"the peer's bytes").await;
    let (state, lease) = (h.state.clone(), h.root_lease());
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        let guard = lease.begin_operation().unwrap();
        state
            .dirty_path_repository()
            .record_dirty_path(GROUP, "dirtied.bin", "created_or_modified", 1, &guard.permit())
            .unwrap();
    }));

    project(&h, "dirtied.bin").await;

    assert!(!h.path("dirtied.bin").exists(), "nothing was renamed into place");
    assert_published_nothing(&h, "dirtied.bin", "dirty journal");
}
