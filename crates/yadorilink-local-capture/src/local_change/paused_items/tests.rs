#![cfg(test)]

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;

use crate::local_change::LocalChangeProcessor;
use crate::test_support::TestReplica;

const GROUP: &str = "group-1";

fn processor() -> (
    LocalChangeProcessor,
    Arc<TestReplica>,
    tempfile::TempDir,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
    let emitter =
        Arc::new(LocalAuthorKey::for_tests("device-a", SigningKey::from_bytes(&[7u8; 32])));
    let proc = LocalChangeProcessor::new(
        state.clone(),
        store,
        "device-a".into(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(emitter);
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let _ = state.link_repository().add_link(&root.to_string_lossy(), GROUP);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP, state.coordinator())
        .unwrap();
    (proc, state, store_dir, root, root_dir)
}

fn flush(root: &std::path::Path, paths: &[&str]) -> DebounceFlush {
    DebounceFlush::Paths(
        paths.iter().map(|p| (root.join(p), FsChangeKind::CreatedOrModified, 1_000)).collect(),
    )
}

/// Every path's authoring change, so a test can tell "nothing new was
/// authored" from "the same thing was re-authored".
fn authoring(state: &TestReplica, paths: &[&str]) -> BTreeMap<String, Option<[u8; 32]>> {
    paths
        .iter()
        .map(|p| {
            let hash = crate::test_support::native_path_head_provenances(state, GROUP, p)
                .into_iter()
                .next();
            (p.to_string(), hash)
        })
        .collect()
}

/// Every capture route holds a paused item -- a watcher flush, a full
/// disk reconcile (which is also what notices an offline deletion) -- and
/// none of them leaves a dirty-journal row behind, which would block
/// remote admission to the path for as long as the pause lasts. Resuming
/// captures the edit, the new file and the deletion, and leaves the
/// unpaused sibling alone.
#[tokio::test]
async fn a_paused_item_is_held_by_every_capture_route_and_captured_on_resume() {
    let (proc, state, _store_dir, root, _root_dir) = processor();
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::write(root.join("dir/a.txt"), b"v1").unwrap();
    std::fs::write(root.join("dir/c.txt"), b"to be deleted").unwrap();
    std::fs::write(root.join("keep.txt"), b"k1").unwrap();
    proc.process_flush(GROUP, &root, flush(&root, &["dir/a.txt", "dir/c.txt", "keep.txt"]))
        .await
        .unwrap();
    let watched = ["dir/a.txt", "dir/b.txt", "dir/c.txt"];
    let before = authoring(&state, &watched);
    assert!(before["dir/a.txt"].is_some() && before["dir/c.txt"].is_some(), "sanity");

    state.paused_item_repository().pause(GROUP, "dir").unwrap();
    std::fs::write(root.join("dir/a.txt"), b"v2 while paused").unwrap();
    std::fs::write(root.join("dir/b.txt"), b"new while paused").unwrap();
    std::fs::remove_file(root.join("dir/c.txt")).unwrap();
    std::fs::write(root.join("keep.txt"), b"k2").unwrap();

    let watcher = proc
        .process_flush(GROUP, &root, flush(&root, &["dir/a.txt", "dir/b.txt", "dir/c.txt"]))
        .await
        .unwrap();
    assert!(watcher.records.is_empty(), "a watcher flush authors nothing under a paused item");
    let scanned = proc.scan_existing_files(GROUP, &root).unwrap();
    assert_eq!(
        scanned.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        vec!["keep.txt"],
        "a full reconcile captures only what is not paused"
    );
    assert_eq!(authoring(&state, &watched), before, "nothing under the paused item is authored");
    for path in watched {
        assert!(
            !state.dirty_path_repository().is_path_dirty(GROUP, path).unwrap(),
            "a held path must not stay journaled dirty: {path}"
        );
    }

    assert!(state.paused_item_repository().resume(GROUP, "dir").unwrap());
    let resumed = proc.capture_resumed_item(GROUP, &root, "dir").await.unwrap();
    let mut captured: Vec<(String, bool)> =
        resumed.records.iter().map(|r| (r.path.clone(), r.deleted)).collect();
    captured.sort();
    assert_eq!(
        captured,
        vec![
            ("dir/a.txt".to_string(), false),
            ("dir/b.txt".to_string(), false),
            ("dir/c.txt".to_string(), true),
        ],
        "resume captures the edit, the new file and the deletion held while paused"
    );
}
