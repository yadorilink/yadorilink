#![cfg(test)]
//! A version that a sync replaces or deletes is put into the block store first, when this device
//! holds it only as a file: the real projection passes, end to end.
//!
//! Each test captures a version (which writes it to the store, as capture does today), takes its
//! blocks out of the store again so that only the user's file holds them, and then lets a peer's
//! signed delta replace or remove the file.

use std::sync::Arc;

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_local_storage::BlockStore;
use yadorilink_replica_domain::ids::{DeltaHash, VersionHash};

use super::delete_projection_tests::{reconcile, Remote};
use super::growing_file_projection_tests::{Harness, GROUP};
use super::version_retention::version_kept_in_store;
use crate::test_support::remote_admission_fixture::{delete, put};

/// Captures `rel` with `bytes`, then takes its blocks out of the store: afterwards only the file
/// holds the version. Returns the head and the blocks.
async fn captured_only_in_its_file(
    h: &Harness,
    rel: &str,
    bytes: &[u8],
) -> (DeltaHash, Vec<yadorilink_replica_domain::file::BlockInfo>) {
    std::fs::write(h.path(rel), bytes).unwrap();
    assert!(matches!(h.capture(rel).await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, rel).unwrap().expect("captured").blocks;
    assert!(!blocks.is_empty(), "fixture: the version has bytes");
    for block in &blocks {
        h.store.delete(&hex::encode(&block.hash)).unwrap();
    }
    assert!(!kept(h, &blocks), "fixture: the store no longer holds the version");
    (DeltaHash(h.own_head(rel).change_hash), blocks)
}

fn kept(h: &Harness, blocks: &[yadorilink_replica_domain::file::BlockInfo]) -> bool {
    let state = Arc::clone(&h.state);
    version_kept_in_store(
        h.store.as_ref(),
        &move |hashes: &[Vec<u8>]| state.group_has_block_provenance_batch(GROUP, hashes),
        blocks,
    )
    .unwrap()
}

/// A peer's delete of a file removes it, and the version it removed is in the store afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_by_a_sync_puts_the_removed_version_into_the_store_first() {
    let h = Harness::new(true);
    let (seen, blocks) =
        captured_only_in_its_file(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert!(attempt.is_settled("notes.txt"));
    assert!(std::fs::symlink_metadata(h.path("notes.txt")).is_err(), "the file is removed");
    assert!(kept(&h, &blocks), "the removed version can still be restored");
}

/// A peer's newer version replaces the file, and the version it replaced is in the store
/// afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_by_a_sync_puts_the_replaced_version_into_the_store_first() {
    let h = Harness::new(true);
    let (old, blocks) = captured_only_in_its_file(&h, "notes.txt", b"older, held here").await;
    std::fs::write(h.path("scratch.bin"), b"newer, from the peer").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![put("notes.txt", newer, vec![old])]).await;

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert!(attempt.is_settled("notes.txt"));
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"newer, from the peer");
    assert!(kept(&h, &blocks), "the replaced version can still be restored");
}

/// The store already holds the version: nothing is read from the file and the version stays kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_the_store_already_holds_stays_kept_through_a_replacement() {
    let h = Harness::new(true);
    std::fs::write(h.path("notes.txt"), b"older, already in the store").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, "notes.txt").unwrap().unwrap().blocks;
    let old = DeltaHash(h.own_head("notes.txt").change_hash);
    assert!(kept(&h, &blocks), "fixture: capture put the version into the store");
    std::fs::write(h.path("scratch.bin"), b"newer").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![put("notes.txt", newer, vec![old])]).await;

    assert!(reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt"));

    assert!(kept(&h, &blocks));
}

/// The store holds the version but one of its blocks is damaged: the proof does not take it for a
/// kept version, and reads the version from the file again, so the replacement leaves a whole
/// version in the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_damaged_block_in_the_store_is_rewritten_from_the_file_before_a_replacement() {
    use yadorilink_local_storage::segment_store::testing::flip_one_payload_bit;
    let h = Harness::new(true);
    std::fs::write(h.path("notes.txt"), b"older, with a damaged copy in the store").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, "notes.txt").unwrap().unwrap().blocks;
    let old = DeltaHash(h.own_head("notes.txt").change_hash);
    // Not looked at before the replacement: a verified read of the damaged block would drop its
    // mapping from the store, and the proof would then find it absent without verifying anything.
    flip_one_payload_bit(h.store_root(), &hex::encode(&blocks[0].hash)).unwrap();
    std::fs::write(h.path("scratch.bin"), b"newer").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![put("notes.txt", newer, vec![old])]).await;

    assert!(reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt"));

    // Read back through the store's own verified read, not through the check under test.
    for block in &blocks {
        h.store
            .get(&hex::encode(&block.hash))
            .expect("the damaged block was rewritten from the file, and reads back verified");
    }
}

/// An editor saves over the file while the version it holds is being kept: the removal does not
/// go ahead. What is at the path afterwards is the editor's file, looked at again by the guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_edited_while_its_version_is_being_kept_is_not_removed() {
    let h = Harness::new(false);
    let (seen, _blocks) =
        captured_only_in_its_file(&h, "notes.txt", b"the version the remover saw").await;
    let mut remote = Remote::new();
    remote.admit(&h, vec![delete("notes.txt", vec![seen])]).await;
    let edited: &[u8] = b"an edit saved while the old version was being kept";
    {
        let path = h.path("notes.txt");
        super::removal_ordering_probe::arm_after_proof(path.clone(), move || {
            let replacement = path.with_extension("tmp-save");
            std::fs::write(&replacement, edited).unwrap();
            std::fs::rename(&replacement, &path).unwrap();
        });
    }

    let attempt = reconcile(&h, &["notes.txt"]).await;

    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        edited,
        "the edit saved during the proofs is not removed"
    );
    assert!(!attempt.is_settled("notes.txt"), "the removal is tried again, not settled");
}

/// A block of the version that a receive pass happens to hold in memory is not a kept block: it is
/// gone when the pass lets go. The version is read into the durable store anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_held_only_in_a_passes_memory_does_not_count_as_kept() {
    use super::window_blocks::WindowBlocksHold;
    let h = Harness::new(true);
    let (old, blocks) =
        captured_only_in_its_file(&h, "notes.txt", b"older, one block of it held in memory").await;
    // The pass holds the old version's block in memory (as a pass receiving an identical block of
    // another file would).
    let mut hold = WindowBlocksHold::new(Arc::clone(&h.convergence.window_blocks), GROUP);
    assert!(hold.try_hold(&hex::encode(&blocks[0].hash), b"older, one block of it held in memory"));
    std::fs::write(h.path("scratch.bin"), b"newer").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer = VersionHash(h.own_head("scratch.bin").content.unwrap().version_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![put("notes.txt", newer, vec![old])]).await;

    assert!(reconcile(&h, &["notes.txt"]).await.is_settled("notes.txt"));

    drop(hold);
    assert!(kept(&h, &blocks), "the durable store holds the replaced version");
}

/// What `yadorilink versions` says about the two kinds of replacement, side by side on one
/// device: the version a sync replaced is held (`kept`), the version this device's own edit
/// replaced is not (`not-kept`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_list_a_sync_replaced_version_as_kept_and_an_own_edit_replaced_one_as_not_kept() {
    use crate::queries::file_history::{content_of_versions, VersionContent};

    let h = Harness::new(true);
    // `synced.txt`: held only by its file, then replaced by a peer's version.
    let (synced_head, synced_blocks) =
        captured_only_in_its_file(&h, "synced.txt", b"replaced by a sync").await;
    std::fs::write(h.path("source.bin"), b"the peer's newer version").unwrap();
    assert!(matches!(h.capture("source.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer = VersionHash(h.own_head("source.bin").content.unwrap().version_hash);
    let mut remote = Remote::new();
    remote.admit(&h, vec![put("synced.txt", newer, vec![synced_head])]).await;
    assert!(reconcile(&h, &["synced.txt"]).await.is_settled("synced.txt"));
    // `edited.txt`: held only by its file, then replaced by the user's own edit.
    let (_, edited_blocks) =
        captured_only_in_its_file(&h, "edited.txt", b"replaced by my edit").await;
    std::fs::write(h.path("edited.txt"), b"my next version, a different length").unwrap();
    assert!(matches!(h.capture("edited.txt").await, LocalChangeOutcome::FileChanged(_)));

    let listed = |rel: &str| {
        let records = h.state.sqlite().dag_list_versions(GROUP, rel).unwrap();
        content_of_versions(h.store.as_ref(), records).unwrap()
    };
    let content_of = |rel: &str, blocks: &[yadorilink_replica_domain::file::BlockInfo]| {
        listed(rel)
            .into_iter()
            .find(|v| v.record.blocks == blocks)
            .unwrap_or_else(|| panic!("{rel}: the older version is listed"))
            .content
    };
    assert_eq!(content_of("synced.txt", &synced_blocks), VersionContent::Kept);
    assert_eq!(content_of("edited.txt", &edited_blocks), VersionContent::NotKept);
    for (rel, older) in [("synced.txt", &synced_blocks), ("edited.txt", &edited_blocks)] {
        let current: Vec<_> =
            listed(rel).into_iter().filter(|v| v.record.blocks != *older).collect();
        assert_eq!(current.len(), 1, "{rel}: one current version");
        assert_eq!(current[0].content, VersionContent::NotApplicable, "{rel}");
    }
}
