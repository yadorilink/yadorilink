//! This is the one materialization test that constructs a real
//! `LocalChangeProcessor`. An external integration test links `yadorilink-daemon` (which
//! owns `ReplicaCoordinator`'s port impls) as an ordinary dev-dependency,
//! the same build this crate's own library code sees, so the coercion is
//! sound here. That assertion is about `LocalChangeProcessor`'s behavior,
//! so this crate is its home, not `yadorilink-filesystem-sync`. The three
//! tiny private helpers this test used
//! (`materialization.rs::tests::{adopt_root, crashed_executable,
//! disk_unix_mode}`) are not `pub`, so they are reproduced here directly
//! rather than widened — each is a few lines with no logic of its own
//! worth sharing.

#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::materialization_repair::{
    repair_interrupted_materializations, RepairMode,
};
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::root_identity::VerifiedRoot;

fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
    let _ = state.link_repository().add_link(&root.to_string_lossy(), group);
    VerifiedRoot::open(root, group, state).unwrap();
    state
        .link_repository()
        .set_capture_volume_identity_for_group(
            group,
            &yadorilink_filesystem_sync::device_boundary::root_volume_identity(root).unwrap(),
        )
        .unwrap();
}

fn record_with_blocks(path: &str, content: &[u8], hash: Vec<u8>) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
        deleted: false,
    }
}

/// Indexes `path` as a `Present` executable whose blocks are all in the
/// store but whose file is missing, with the materialization intent a crash
/// mid-write leaves behind — the exact state repair reconstructs from.
fn crashed_executable(
    state: &ReplicaCoordinator,
    store: &SegmentBlockStore,
    path: &str,
    content: &[u8],
) {
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record_with_blocks(path, content, hash),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_unix_mode("group-1", path, Some(0o755), &RootCommitPermit::for_tests())
        .unwrap();
    // A fresh `upsert_file` row defaults to `Remote` (schema v25's
    // fail-closed default -- see `upsert_file_in_tx`'s own doc comment), not
    // `Present`. This fixture simulates a device that had already
    // materialized the file before crashing mid-rewrite, so it must stamp
    // `Present` explicitly; without this, `repair_interrupted_
    // materializations_inner`'s candidate loop skips the row entirely
    // (it only considers rows snapshotted as `Present`) and repair never
    // sees "tool.sh" at all.
    state
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            path,
            MaterializationState::Present,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", path, &[0u8; 32], &RootCommitPermit::for_tests())
        .unwrap();
}

fn disk_unix_mode(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o100 != 0
}

/// End-to-end over the seam that decides how bad a dropped exec bit is: a
/// repair followed by the startup scan the daemon runs next.
///
/// `reconstruct_file_journaled`'s own `apply_unix_mode` call (right after the
/// reconstruct) already reapplies the index's recorded exec bit to the
/// repaired file, so by the time the scan runs, disk and index already agree
/// — the scan mints nothing to report either way, and this test asserts that
/// agreement holds across it. `reconstruct_file` also now stamps the
/// repaired file's on-disk mtime to the indexed `mtime_unix_nanos` (0 here),
/// so the scan's size+mtime fast path fires directly rather than falling
/// through to the slower full chunk-and-compare self-echo path; either path
/// reaches the same "nothing changed" verdict once exec bit already agrees,
/// so this is not itself part of what the assertions below check.
#[test]
fn repair_leaves_disk_unix_mode_agreeing_with_the_index_across_a_scan() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    crashed_executable(&state, &store, "tool.sh", b"#!/bin/sh\necho hello\n");

    let report = repair_interrupted_materializations(
        state.as_ref(),
        store.as_ref(),
        root.path(),
        "group-1",
        RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert_eq!(report.reconstructed, vec!["tool.sh".to_string()]);

    let minted = yadorilink_local_capture::LocalChangeProcessor::new(
        state.clone(),
        store.clone(),
        "device-a".to_string(),
        Arc::new(RootLease::for_tests()),
    )
    .scan_existing_files("group-1", root.path())
    .unwrap();

    assert!(
        minted.is_empty(),
        "the scan suppresses the repaired file as a self-echo, so it can neither propagate \
         a dropped exec bit nor repair one: {minted:?}"
    );
    assert_eq!(
        state.file_index_repository().get_unix_mode("group-1", "tool.sh").unwrap(),
        Some(0o755),
        "the index keeps unix_mode=Some(0o755) across the scan"
    );
    assert!(
        disk_unix_mode(&root.path().join("tool.sh")),
        "so the disk must already agree with it -- no later pass reconciles the two"
    );
}
