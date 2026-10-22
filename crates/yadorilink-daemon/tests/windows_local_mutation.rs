//! Proves the platform-neutral local-change pipeline
//! (`LocalChangeProcessor::scan_existing_files`, the same classification
//! logic a live filesystem watcher's `process_event` uses for a
//! `CreatedOrModified` event) captures ordinary files on Windows through
//! a real `ReplicaCoordinator`, whose
//! `LocalMutationStore::inspect_windows_placeholder` impl calls the real
//! `placeholder_inspect_windows::inspect_placeholder`. No Windows-specific
//! sync logic: the common DAG path handles Windows create/modify/delete.
//!
//! The dirty-detection verdicts themselves (`Untouched`/`Dirty`/`Unknown`)
//! are covered with a fake inspector by `local_change`'s own Windows unit
//! tests.
#![cfg(windows)]

use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_root_authority::root_commit::RootLease;
use yadorilink_root_authority::root_identity::VerifiedRoot;

fn unique_temp_root() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    dir.push(format!("yadorilink-local-mutation-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
    let _ = state.link_repository().add_link(&root.to_string_lossy(), group);
    VerifiedRoot::open(root, group, state).unwrap();
}

fn processor(
    state: Arc<ReplicaCoordinator>,
    store: Arc<SegmentBlockStore>,
) -> yadorilink_local_capture::LocalChangeProcessor {
    yadorilink_local_capture::LocalChangeProcessor::new(
        state,
        store,
        "device-a".to_string(),
        Arc::new(RootLease::for_tests()),
    )
}

/// An ordinary file the user created directly (never a CfAPI placeholder
/// at all -- no recorded generation) must be captured normally. Proves
/// the Windows dirty-detection path does not accidentally suppress
/// genuine new files that were never placeholders.
#[test]
fn an_ordinary_new_file_with_no_placeholder_history_is_captured_normally() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = unique_temp_root();
    adopt_root(&state, "group-1", &root);

    std::fs::write(root.join("new-file.txt"), b"never a placeholder").unwrap();

    let minted =
        processor(state.clone(), store.clone()).scan_existing_files("group-1", &root).unwrap();
    let minted_paths: Vec<String> = minted.iter().map(|r| r.path.clone()).collect();

    assert_eq!(
        minted_paths,
        vec!["new-file.txt".to_string()],
        "a plain new file with no CfAPI history must be captured as a local change: {minted:?}"
    );

    if let Err(e) = std::fs::remove_dir_all(&root) {
        eprintln!("warning: failed to clean up test root {}: {e}", root.display());
    }
}
