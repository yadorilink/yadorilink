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
    let directory = FileVersion::directory(None);
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
