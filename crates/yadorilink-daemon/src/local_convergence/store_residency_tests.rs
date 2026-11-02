#![cfg(test)]
//! The current versions of files are brought into the block store from the files that hold them,
//! and a file that is no longer its version is not refused but journaled for capture.
//!
//! Each test captures a version (which writes it to the store, as capture does today) and takes
//! its blocks out again, so that only the user's file holds it: the state a hash-only capture, or
//! a received version, leaves.

use std::sync::Arc;

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_local_storage::{BlockContentStore, BlockStore};
use yadorilink_replica_domain::file::BlockInfo;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::version_retention::version_kept_in_store;
use crate::store_residency::{bring_current_versions_into_store_with, Residency};

async fn captured_only_in_its_file(h: &Harness, rel: &str, bytes: &[u8]) -> Vec<BlockInfo> {
    std::fs::write(h.path(rel), bytes).unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, rel).unwrap().expect("captured").blocks;
    assert!(!blocks.is_empty(), "fixture: the version has bytes");
    for block in &blocks {
        h.store.delete(&hex::encode(&block.hash)).unwrap();
    }
    assert!(!kept(h, &blocks), "fixture: the store no longer holds the version");
    blocks
}

fn kept(h: &Harness, blocks: &[BlockInfo]) -> bool {
    let state = Arc::clone(&h.state);
    version_kept_in_store(
        h.store.as_ref(),
        &move |hashes: &[Vec<u8>]| state.group_has_block_provenance_batch(GROUP, hashes),
        blocks,
    )
    .unwrap()
}

async fn bring(h: &Harness, prefix: &str) -> Residency {
    let store: Arc<dyn BlockContentStore + Send + Sync> =
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(h.store.clone()));
    let root = h.path("x").parent().unwrap().to_path_buf();
    let lease = h.root_lease();
    bring_current_versions_into_store_with(
        &h.state,
        &store,
        &|| Ok((root.clone(), lease.clone())),
        GROUP,
        prefix,
        true,
    )
    .await
    .unwrap()
}

fn journaled(h: &Harness, rel: &str) -> bool {
    h.state.dirty_path_repository().dirty_path_observed_at(GROUP, rel).unwrap().is_some()
}

/// A version held only by its file is read into the store, verified, with the group's provenance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_held_only_by_its_file_is_read_into_the_store() {
    let h = Harness::new(true);
    let blocks = captured_only_in_its_file(&h, "notes.txt", b"held by the file alone").await;

    assert_eq!(bring(&h, "").await, Residency::InStore);

    assert!(kept(&h, &blocks), "the version is in the store, durable, with provenance");
}

/// A version the store already holds is not read from the file: the file can be gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_the_store_holds_needs_no_file() {
    let h = Harness::new(true);
    std::fs::write(h.path("kept.txt"), b"already in the store").unwrap();
    assert!(matches!(h.capture("kept.txt").await, LocalChangeOutcome::FileChanged(_)));
    std::fs::remove_file(h.path("kept.txt")).unwrap();

    assert_eq!(bring(&h, "").await, Residency::InStore);
    assert!(!journaled(&h, "kept.txt"), "nothing was asked of capture");
}

/// The folder (and the root lease) are looked up only when a file has to be read: a device whose
/// folder is unmounted, or whose link is not watching, still answers for what its store holds, and
/// a file it would have to read fails with the lookup's own error, not a generic refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_folder_is_looked_up_only_for_a_file_that_has_to_be_read() {
    let h = Harness::new(true);
    let store: Arc<dyn BlockContentStore + Send + Sync> =
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(h.store.clone()));
    let unmounted =
        || Err(crate::sync_error::SyncError::NotFound("the folder is not mounted".to_owned()));

    std::fs::write(h.path("kept.txt"), b"already in the store").unwrap();
    assert!(matches!(h.capture("kept.txt").await, LocalChangeOutcome::FileChanged(_)));
    let held = crate::store_residency::bring_current_versions_into_store_with(
        &h.state, &store, &unmounted, GROUP, "", true,
    )
    .await;
    assert_eq!(held.unwrap(), Residency::InStore, "everything is in the store: no folder needed");

    captured_only_in_its_file(&h, "file-only.txt", b"only the file holds this").await;
    let needed = crate::store_residency::bring_current_versions_into_store_with(
        &h.state, &store, &unmounted, GROUP, "", true,
    )
    .await;
    assert!(
        matches!(&needed, Err(crate::sync_error::SyncError::NotFound(m)) if m.contains("not mounted")),
        "{needed:?}"
    );
}

/// A file edited since its record is not the version: it is not refused, it is journaled for
/// capture, and the caller is told it is not in the store yet. Nothing is put into the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_edited_since_its_record_is_journaled_for_capture() {
    let h = Harness::new(true);
    let blocks = captured_only_in_its_file(&h, "edited.txt", b"the version on record").await;
    std::fs::write(h.path("edited.txt"), b"an edit nobody has captured, other length").unwrap();

    assert_eq!(bring(&h, "").await, Residency::Pending(vec!["edited.txt".to_owned()]));

    assert!(journaled(&h, "edited.txt"), "capture is asked to read the file");
    assert!(!kept(&h, &blocks), "the old version is not in the store: its bytes are gone");
}

/// A file that is gone is journaled as removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_is_gone_is_journaled_as_removed() {
    let h = Harness::new(true);
    captured_only_in_its_file(&h, "gone.txt", b"removed since its record").await;
    std::fs::remove_file(h.path("gone.txt")).unwrap();

    assert_eq!(bring(&h, "").await, Residency::Pending(vec!["gone.txt".to_owned()]));
    assert!(journaled(&h, "gone.txt"));
}

/// Only the files beneath the prefix are looked at; a changed file elsewhere is not this call's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_prefix_is_looked_at() {
    let h = Harness::new(true);
    std::fs::create_dir_all(h.path("pinned")).unwrap();
    let inside = captured_only_in_its_file(&h, "pinned/in.txt", b"beneath the prefix").await;
    captured_only_in_its_file(&h, "other.txt", b"elsewhere").await;
    std::fs::write(h.path("other.txt"), b"changed, and not this call's business").unwrap();

    assert_eq!(bring(&h, "pinned").await, Residency::InStore);

    assert!(kept(&h, &inside));
    assert!(!journaled(&h, "other.txt"));
}

/// A prefix that is itself a file is brought into the store too (a pin of one file).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prefix_that_is_a_file_is_brought_into_the_store() {
    let h = Harness::new(true);
    let blocks = captured_only_in_its_file(&h, "single.txt", b"a pinned file").await;

    assert_eq!(bring(&h, "single.txt").await, Residency::InStore);

    assert!(kept(&h, &blocks));
}

fn set_state(
    h: &Harness,
    rel: &str,
    state: yadorilink_replica_domain::session_state::MaterializationState,
) {
    h.state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            rel,
            state,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
}

/// A file still being received is not settled: the receive may finish after this pass with the
/// version held by its file alone. It is pending, not done, and nothing is journaled (there is no
/// edit to capture). A placeholder holds no bytes here and is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_still_being_received_is_pending_and_a_placeholder_is_done() {
    use yadorilink_replica_domain::session_state::MaterializationState;
    let h = Harness::new(true);
    captured_only_in_its_file(&h, "arriving.txt", b"a receive is still finishing").await;
    captured_only_in_its_file(&h, "placeholder.txt", b"no object here").await;
    set_state(&h, "arriving.txt", MaterializationState::Hydrating);
    set_state(&h, "placeholder.txt", MaterializationState::Remote);

    assert_eq!(bring(&h, "").await, Residency::Pending(vec!["arriving.txt".to_owned()]));

    assert!(!journaled(&h, "arriving.txt"), "nothing to capture: the file is not an edit");
    assert!(!journaled(&h, "placeholder.txt"));
}

/// A caller that must not wait for a path lock (one running under it, as a restore announcing its
/// commit does) is told the path is pending instead of being blocked behind its own lock; once the
/// lock is free the same call reads the version in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_that_does_not_wait_finds_a_held_path_pending() {
    let h = Harness::new(true);
    let blocks = captured_only_in_its_file(&h, "held.txt", b"held by the file alone").await;
    let store: Arc<dyn BlockContentStore + Send + Sync> =
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(h.store.clone()));
    let root = h.path("x").parent().unwrap().to_path_buf();
    let lease = h.root_lease();
    let folder = || Ok((root.clone(), lease.clone()));

    let lock = h.state.path_lock_registry().path_lock(GROUP, "held.txt");
    let guard = lock.clone().lock_owned().await;
    let pending = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::store_residency::bring_current_versions_into_store_with(
            &h.state, &store, &folder, GROUP, "held.txt", false,
        ),
    )
    .await
    .expect("not waiting for the lock means not hanging on it")
    .unwrap();
    assert_eq!(pending, Residency::Pending(vec!["held.txt".to_owned()]));
    assert!(!kept(&h, &blocks), "nothing was read while the lock was held");

    drop(guard);
    let settled = crate::store_residency::bring_current_versions_into_store_with(
        &h.state, &store, &folder, GROUP, "held.txt", false,
    )
    .await
    .unwrap();
    assert_eq!(settled, Residency::InStore);
    assert!(kept(&h, &blocks));
}
