#![cfg(test)]
//! A device's own edit or delete is not held up by history, and does not put the version it
//! replaced into the block store.
//!
//! The owner decided that the version an edit replaces is not guaranteed (a sync that replaces a
//! version is: `version_retention_flow_tests`). An edit has already changed the file by the time it
//! is captured, so the replaced version's bytes are no longer anywhere to be read from; the rule
//! therefore asks nothing of the capture, and these tests pin that, so a later change that adds a
//! proof to the capture path cannot start refusing the user's own edits.

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_local_storage::BlockStore;
use yadorilink_replica_domain::file::BlockInfo;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::version_retention::version_kept_in_store;

/// Captures `rel` with `bytes`, then takes its blocks out of the store: afterwards only the file
/// holds the version.
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
    let state = std::sync::Arc::clone(&h.state);
    version_kept_in_store(
        h.store.as_ref(),
        &move |hashes: &[Vec<u8>]| state.group_has_block_provenance_batch(GROUP, hashes),
        blocks,
    )
    .unwrap()
}

/// The user saves a new version over a file whose previous version is held only by that file's
/// old bytes: the capture goes through, and the previous version is not brought into the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_own_edit_is_captured_and_does_not_keep_the_version_it_replaced() {
    let h = Harness::new(true);
    let before = captured_only_in_its_file(&h, "notes.txt", b"the version the edit replaces").await;

    std::fs::write(h.path("notes.txt"), b"the user's next version, a different length").unwrap();
    let outcome = h.capture("notes.txt").await;

    assert!(matches!(outcome, LocalChangeOutcome::FileChanged(_)), "the edit is captured");
    let current = h.state.get_file(GROUP, "notes.txt").unwrap().expect("a current row");
    assert!(!current.deleted);
    assert_ne!(current.blocks, before, "the current version is the edit");
    assert!(kept(&h, &current.blocks), "the new version is in the store, as capture puts it");
    assert!(!kept(&h, &before), "the replaced version is not guaranteed and is not ingested");
}

/// The user deletes a file: the delete is captured, and the deleted version is not kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_own_delete_is_captured_and_does_not_keep_the_version_it_removed() {
    let h = Harness::new(true);
    let before = captured_only_in_its_file(&h, "gone.txt", b"the version the delete removes").await;

    std::fs::remove_file(h.path("gone.txt")).unwrap();
    let outcome = h.observe_removal("gone.txt").await;

    assert!(
        matches!(outcome, LocalChangeOutcome::FileChanged(_)),
        "the delete is captured, got {outcome:?}"
    );
    let current = h.state.get_file(GROUP, "gone.txt").unwrap().expect("a tombstone row");
    assert!(current.deleted, "the current row is the user's delete");
    assert!(!kept(&h, &before), "the removed version is not guaranteed and is not ingested");
}
