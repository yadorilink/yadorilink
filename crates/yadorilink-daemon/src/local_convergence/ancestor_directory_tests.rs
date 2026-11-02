#![cfg(test)]
//! A directory the pass only passes through -- the ancestor of a path being
//! settled -- is not settled again when nothing about it could change, and is
//! whenever anything could: a new head, a delete, a rename, a contest, a write
//! begun since its proof, or an edit on disk.
//!
//! "Settled again" is observed through the path's mutation fence, which every
//! directory write bumps before it touches disk and nothing else moves.

use super::growing_file_projection_tests::{Harness, GROUP};
use super::*;
use crate::test_support::remote_admission_fixture::{admit_remote_ops, Basis};
use std::collections::BTreeSet;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;

fn put(path: &str, version: VersionHash) -> Op {
    Op::Put { path: SyncPath(path.into()), version }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

fn store(h: &Harness, versions: &[&FileVersion]) {
    h.state
        .database()
        .write(|conn| {
            for version in versions {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
}

fn remote(h: &Harness, device: &str, ops: &[Op], basis: Basis, versions: &[&FileVersion]) {
    store(h, versions);
    admit_remote_ops(&h.state, GROUP, device, ops, basis);
}

async fn stored_version(h: &Harness, scratch: &str, bytes: &[u8]) -> VersionHash {
    std::fs::write(h.path(scratch), bytes).unwrap();
    assert!(matches!(h.capture(scratch).await, LocalChangeOutcome::FileChanged(_)));
    VersionHash(h.own_head(scratch).content.unwrap().version_hash)
}

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

async fn reconcile(h: &Harness, paths: &[&str]) -> ProjectionAttempt {
    let paths: BTreeSet<String> = paths.iter().map(|p| p.to_string()).collect();
    h.convergence
        .reconcile_paths_directly(&driver(h), GROUP, paths)
        .await
        .unwrap()
        .expect("the pass runs")
}

async fn settle(h: &Harness, paths: &[&str]) {
    for _ in 0..3 {
        if reconcile(h, paths).await.retry.is_empty() {
            return;
        }
    }
    panic!("{paths:?} did not settle");
}

fn fence(h: &Harness, path: &str) -> i64 {
    h.state.dag_snapshot_mutation_fence(GROUP, path).unwrap()
}

fn mode(h: &Harness, path: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(h.path(path)).unwrap().permissions().mode() & 0o777
}

/// `d` (mode 0755) and `d/f1`, both settled on this device.
async fn settled_directory(h: &Harness) -> VersionHash {
    let f1 = stored_version(h, "scratch-f1", b"first child").await;
    let d = FileVersion::directory();
    remote(
        h,
        "device-remote",
        &[put("d", d.version_hash), put("d/f1", f1)],
        Basis::CurrentHeads,
        &[&d],
    );
    settle(h, &["d", "d/f1"]).await;
    assert!(h.path("d").is_dir());
    assert_eq!(mode(h, "d"), 0o755);
    d.version_hash
}

/// Skip the whole test where the temp dir cannot prove object identity (the
/// proof the skip rests on is then never confirmable, and the settle always runs).
macro_rules! need_identity {
    () => {
        if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
            return;
        }
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_converged_ancestor_is_not_settled_again_while_children_arrive() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    let before = fence(&h, "d");
    for i in 2..5 {
        let name = format!("d/f{i}");
        let version = stored_version(&h, &format!("scratch-{i}"), name.as_bytes()).await;
        remote(&h, "device-remote", &[put(&name, version)], Basis::CurrentHeads, &[]);
        let attempt = reconcile(&h, &[&name]).await;
        assert!(attempt.is_settled(&name), "{:?}", attempt.retry);
        assert!(attempt.is_settled("d"), "the ancestor is part of the pass's outcome");
        assert_eq!(std::fs::read(h.path(&name)).unwrap(), name.as_bytes());
    }
    assert_eq!(fence(&h, "d"), before, "a converged ancestor was written again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_begun_since_the_proof_is_not_skipped() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    // A write in flight: its fence bump is all that is visible of it.
    let in_flight = h.state.dag_bump_mutation_fence(GROUP, "d", "test_write").unwrap();
    let child = stored_version(&h, "scratch-c", b"second child").await;
    remote(&h, "device-remote", &[put("d/f2", child)], Basis::CurrentHeads, &[]);

    let attempt = reconcile(&h, &["d/f2"]).await;

    assert!(attempt.is_settled("d/f2"), "{:?}", attempt.retry);
    assert!(fence(&h, "d") > in_flight, "the ancestor was not settled for real");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ancestor_edited_on_disk_is_not_skipped() {
    need_identity!();
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(true);
    settled_directory(&h).await;
    let before = fence(&h, "d");
    std::fs::set_permissions(h.path("d"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let child = stored_version(&h, "scratch-c", b"second child").await;
    remote(&h, "device-remote", &[put("d/f2", child)], Basis::CurrentHeads, &[]);

    reconcile(&h, &["d/f2"]).await;

    assert_ne!(fence(&h, "d"), before, "an edited ancestor was taken for converged");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_child_delete_leaves_the_converged_ancestor_alone() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    let before = fence(&h, "d");
    remote(&h, "device-remote", &[delete("d/f1")], Basis::CurrentHeads, &[]);

    let attempt = reconcile(&h, &["d/f1"]).await;

    assert!(attempt.is_settled("d/f1"), "{:?}", attempt.retry);
    assert!(!h.path("d/f1").exists());
    assert!(h.path("d").is_dir());
    assert_eq!(fence(&h, "d"), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_ancestor_with_a_live_child_is_kept_as_a_container() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    remote(&h, "device-remote", &[delete("d")], Basis::CurrentHeads, &[]);

    let attempt = reconcile(&h, &["d/f1"]).await;

    assert!(attempt.is_settled("d/f1"), "{:?}", attempt.retry);
    assert!(h.path("d").is_dir());
    assert_eq!(std::fs::read(h.path("d/f1")).unwrap(), b"first child");
    settle(&h, &["d"]).await;
    assert!(h.path("d/f1").exists(), "the child outlives the deleted directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renamed_ancestor_is_built_under_its_new_name() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    let e = FileVersion::directory();
    let moved = stored_version(&h, "scratch-m", b"first child").await;
    remote(
        &h,
        "device-remote",
        &[delete("d/f1"), delete("d"), put("e", e.version_hash), put("e/f1", moved)],
        Basis::CurrentHeads,
        &[&e],
    );

    let attempt = reconcile(&h, &["e/f1"]).await;

    assert!(attempt.is_settled("e/f1"), "{:?}", attempt.retry);
    assert!(h.path("e").is_dir());
    assert_eq!(std::fs::read(h.path("e/f1")).unwrap(), b"first child");
    settle(&h, &["d", "d/f1"]).await;
    assert!(!h.path("d/f1").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_contested_by_a_file_is_left_alone() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    let before = fence(&h, "d");
    let file = stored_version(&h, "scratch-d", b"a file where a directory stands").await;
    remote(&h, "device-one", &[put("d", file)], Basis::Nothing, &[]);
    let child = stored_version(&h, "scratch-c", b"second child").await;
    remote(&h, "device-remote", &[put("d/f2", child)], Basis::CurrentHeads, &[]);

    reconcile(&h, &["d/f2"]).await;

    assert!(h.path("d").is_dir());
    assert_eq!(std::fs::read(h.path("d/f1")).unwrap(), b"first child");
    assert!(
        fence(&h, "d") >= before,
        "the fence never moves backwards; a contested directory is never taken as converged"
    );
}

/// Runs `inject` on the probing thread at the next volume probe -- the await
/// between the skip's last fence read and its decision -- then reconciles
/// `d/f2` and returns the pass with the evidence it adopted for `d`.
async fn reconcile_with_injection_in_hazard_await(
    h: &Harness,
    inject: impl FnOnce() + Send + 'static,
) -> ProjectionAttempt {
    let root = h.convergence.sync_root(GROUP).unwrap();
    // A kept answer would skip the probe, and with it the await.
    h.convergence.volume_probes.forget();
    super::volume_probe::PROBE_HOOKS.lock().unwrap().push((root.clone(), Box::new(inject)));
    let attempt = reconcile(h, &["d/f2"]).await;
    assert!(
        !super::volume_probe::PROBE_HOOKS.lock().unwrap().iter().any(|(r, _)| *r == root),
        "the injection never ran: the hazard await was not reached"
    );
    attempt
}

/// Whether the evidence adopted for `d` could still be published as current.
fn publishes_as_current(h: &Harness, attempt: &ProjectionAttempt) -> bool {
    let (exact, generation) = attempt
        .evidence_for("d")
        .expect("the ancestor is part of the pass's outcome")
        .as_exact_actual_state()
        .expect("an exact settlement");
    h.state
        .dag_publish_materialized_generation_if_fence_current(
            GROUP,
            "d",
            exact,
            generation,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap()
}

/// A write that begins (and edits the directory) after the skip's last fence
/// read, while the name-hazard check awaits: the skip may stand, since it
/// writes nothing, but the proof it hands on carries the fence read before the
/// write, so the publication CAS refuses it and the directory is settled for
/// real by the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_during_the_hazard_await_leaves_a_proof_that_cannot_publish() {
    need_identity!();
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(true);
    settled_directory(&h).await;
    let child = stored_version(&h, "scratch-c", b"second child").await;
    remote(&h, "device-remote", &[put("d/f2", child)], Basis::CurrentHeads, &[]);
    let (state, d_path) = (h.state.clone(), h.path("d"));
    let before = fence(&h, "d");

    let attempt = reconcile_with_injection_in_hazard_await(&h, move || {
        state.dag_bump_mutation_fence(GROUP, "d", "test_write").unwrap();
        std::fs::set_permissions(&d_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    })
    .await;

    assert!(attempt.is_settled("d/f2"), "{:?}", attempt.retry);
    assert_eq!(std::fs::read(h.path("d/f2")).unwrap(), b"second child");
    assert!(fence(&h, "d") > before, "the write's fence bump is lost");
    assert!(!publishes_as_current(&h, &attempt), "a proof that predates the write published");
    let after_write = fence(&h, "d");
    settle(&h, &["d"]).await;
    assert!(fence(&h, "d") > after_write, "the edited directory was not settled afterwards");
    assert_eq!(std::fs::read(h.path("d/f1")).unwrap(), b"first child");
}

/// A directory has one canonical version, so another author's head of it is the same version under a
/// new dot. A pass over a child must still settle the ancestor against the heads as they are now.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_version_head_of_another_author_is_settled_with_the_child() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    let again = FileVersion::directory();
    remote(&h, "device-one", &[put("d", again.version_hash)], Basis::Nothing, &[&again]);
    let child = stored_version(&h, "scratch-c", b"second child").await;
    remote(&h, "device-remote", &[put("d/f2", child)], Basis::CurrentHeads, &[]);

    let attempt = reconcile(&h, &["d/f2"]).await;

    assert!(attempt.is_settled("d/f2"), "{:?}", attempt.retry);
    assert!(attempt.is_settled("d"), "the ancestor is part of the pass's outcome");
    assert!(h.path("d").is_dir());
    assert_eq!(std::fs::read(h.path("d/f2")).unwrap(), b"second child");
    // The concurrent heads of one version are then superseded by one resolution.
    let resolved = FileVersion::directory();
    remote(&h, "device-one", &[put("d", resolved.version_hash)], Basis::CurrentHeads, &[&resolved]);
    let attempt = reconcile(&h, &["d/f2"]).await;
    assert!(attempt.is_settled("d/f2"), "{:?}", attempt.retry);
    assert!(attempt.is_settled("d"));
}

/// A head of the ancestor admitted while the pass awaits the hazard check is not confirmed by the
/// settlement the pass publishes: the next pass settles it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_head_during_the_hazard_await_is_not_confirmed_by_the_old_settlement() {
    need_identity!();
    let h = Harness::new(true);
    settled_directory(&h).await;
    let child = stored_version(&h, "scratch-c", b"second child").await;
    remote(&h, "device-remote", &[put("d/f2", child)], Basis::CurrentHeads, &[]);
    let d2 = FileVersion::directory();
    let admit = {
        let state = h.state.clone();
        move || {
            state
                .database()
                .write(|conn| yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &d2))
                .unwrap();
            admit_remote_ops(
                &state,
                GROUP,
                "device-remote",
                &[put("d", d2.version_hash)],
                Basis::CurrentHeads,
            );
        }
    };

    let attempt = reconcile_with_injection_in_hazard_await(&h, admit).await;

    assert!(attempt.is_settled("d/f2"), "{:?}", attempt.retry);
    publishes_as_current(&h, &attempt);
    settle(&h, &["d"]).await;
    assert!(h.path("d").is_dir());
    assert_eq!(std::fs::read(h.path("d/f1")).unwrap(), b"first child");
    assert_eq!(std::fs::read(h.path("d/f2")).unwrap(), b"second child");
}

/// An explicit-directory write that stops right after the directory was created (a crash before
/// its proof commit) has already said so: a user who then removes the directory and restarts the
/// daemon keeps that delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_write_stopped_after_its_creation_leaves_a_user_delete_standing() {
    need_identity!();
    let h = Harness::new(true);
    let d = FileVersion::directory();
    remote(&h, "device-remote", &[put("d", d.version_hash)], Basis::CurrentHeads, &[&d]);
    super::types::placed_hook::set(
        &h.path("d"),
        Box::new(|| panic!("the power went out after the directory was created")),
    );
    let stopped = {
        let (convergence, driver) = (h.convergence.clone(), driver(&h));
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["d".to_owned()]))
                .await
        })
        .await
    };
    assert!(stopped.is_err_and(|e| e.is_panic()), "setup: the write stopped after creating d");
    assert!(h.path("d").is_dir(), "setup: the directory was created");
    assert!(
        h.state.has_materialization_intent(GROUP, "d").unwrap(),
        "setup: the intent is still open"
    );

    std::fs::remove_dir(h.path("d")).unwrap();
    let report = super::receive_deferred_flush_tests::startup(&h);

    assert!(!h.path("d").exists(), "the user's delete was undone by repair: {report:?}");
}
